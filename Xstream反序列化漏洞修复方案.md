## Xstream反序列化漏洞修复方案

### 漏洞描述 
程序在使用Xstream的fromXML方法将xml数据反序列化为java对象时。当输入的xml数据可以被用户控制，那么攻击者可以通过构造恶意输入，让反序列化产生非预期的对象，在此过程中执行构造的任意代码。

### 漏洞示例
漏洞代码示例如下：

``` java
  ......
  //读取对象输入流,并进行反序列化
  InputStream importStream = importFile.getInputStream();
  importXML = IOUtils.toString(importStream, "UTF-8");
  XStream xStream = new XStream();
  //调用fromXML进行反序列化
  importData = (Myclassname) xStream.fromXML(importXML);
  ......
```

代码中直接利用可被用户控制的请求输入xml数据作为fromXML的参数使用，这里输入可能是输入流、文件、post参数等。并且没有设置允许反序列化类的白名单，即可确认存在反序列化漏洞。

### 修复方案

如果可以明确反序列化对象的类名，则可在反序列化时设置允许被反序列化类的白名单（推荐），具体实现方法如下:

#### 使用白名单校验方案(推荐)
使用Xstream的addPermission方法来实现白名单控制，示例代码如下:

``` java
XStream xstream = new XStream();
// 首先清除默认设置，然后进行自定义设置
xstream.addPermission(NoTypePermission.NONE);
// 添加一些基础的类型，如Array、NULL、primitive
xstream.addPermission(ArrayTypePermission.ARRAYS);
xstream.addPermission(NullPermission.NULL);
xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
// 添加自定义的类列表
stream.addPermission(new ExplicitTypePermission(new Class[]{Date.class}));
// 添加同一个package下的多个类型
xstream.allowTypesByWildcard(new String[] {Blog.class.getPackage().getName()+".*"});
```
可以根据业务需求设置白名单。在设置前一定要清除默认设置，即addPermission(NoTypePermission.NONE)。Xstream内置了很多类型，可以参考[Xstream官方示例](http://x-stream.github.io/security.html#example)

#### 使用黑名单校验方案
使用Xstream的denyPermission方法可以实现黑名单控制，但不推荐使用该方法，如果业务需求只能使用黑名单的方式，可以联系安全工程师确认。

### 安全建议

1. 业务需要使用反序列化操作时，尽量避免反序列化数据由外部输入，这样可避免被恶意用户控制
2. 更新org.codehaus.groovy等第三方依赖库版本,已公开的关于xstream反序列化漏洞利用方式是通过Groovy的漏洞CVE-2015-3253，只要Groovy版本在1.7.0至2.4.3之间都受影响。所以建议修复本漏洞的同时也更新groovy等依赖库的版本

### 参考文档
* [应用安全:JAVA反序列化漏洞之殇](https://github.com/Cryin/Paper/blob/master/%E5%BA%94%E7%94%A8%E5%AE%89%E5%85%A8:JAVA%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E4%B9%8B%E6%AE%87.md)
* [Xstream官方示例](http://x-stream.github.io/security.html#example)

