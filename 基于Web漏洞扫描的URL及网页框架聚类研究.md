### 基于Web漏洞扫描的URL及网页框架聚类研究
> from https://github.com/Cryin/Paper

当前WEB漏洞扫描产品在扫描站点时，针对同一类URL(尤其是rewrite后的url，无法像传统静态页面进行去重)、框架下的网页存在相同的安全漏洞会进行重复扫描，这个过程会消耗大量时间和性能。将同类URL及页面进行聚类，选取一个URL页面链接代表整类链接进行扫描，从而能够极大地提升扫描器的扫描效率。

在研究完整个课题并开发完成项目后，才发现yahoo的研究人员早在2008年就提出了完全相似的设计及实现方法。
![](http://i1.piimg.com/567571/278a528e18b420a5.png)
从这张截图就可看出整个方案的思路和流程，不敢相信尽如此巧合。在设计方案时完全没有找到并阅读这个专利。也感叹国外技术发展之早。现将研究参考资料整理如下，感谢这些富有分享精神的技术研究人员。如果有研究该技术的朋友或许能参考：

* [Python实现的treelib，树状存储，基于层次聚类URL链接](https://github.com/caesar0301/treelib)
* [simhash算法原理及实现，基于内容、框架的聚类](http://yanyiwu.com/work/2014/01/30/simhash-shi-xian-xiang-jie.html)
* [海量数据相似度计算之simhash和海明距离](http://www.lanceyan.com/tech/arch/simhash_hamming_distance_similarity.html)
* [海量数据相似度计算之simhash短文本查找](http://www.lanceyan.com/tech/arch/simhash_hamming_distance_similarity2-html.html)
* [TECHNIQUES FOR CLUSTERING STRUCTURALLY SIMILAR WEB PAGES](https://www.google.com/patents/US20080010291)
* [浅谈动态爬虫与去重](http://bobao.360.cn/learning/detail/3391.html)
