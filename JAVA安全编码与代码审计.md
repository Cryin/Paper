## JAVA安全编码与代码审计

### 概述

本文重点介绍JAVA安全编码与代码审计基础知识，会以漏洞及安全编码示例的方式介绍JAVA代码中常见Web漏洞的形成及相应的修复方案，同时对一些常见的漏洞函数进行例举。

### XXE

##### 介绍 

XML文档结构包括XML声明、DTD文档类型定义（可选）、文档元素。文档类型定义(DTD)的作用是定义 XML 文档的合法构建模块。DTD 可以在 XML 文档内声明，也可以外部引用。

* 内部声明DTD:

> <!DOCTYPE 根元素 [元素声明]>

* 引用外部DTD:

> <!DOCTYPE 根元素 SYSTEM "文件名">

当允许引用外部实体时，恶意攻击者即可构造恶意内容访问服务器资源,如读取passwd文件：

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [
<!ENTITY test SYSTEM "file:///ect/passwd">]>
<msg>&test;</msg>
```

##### 漏洞示例
此处以org.dom4j.io.SAXReader为例,仅展示部分代码片段：

```
String xmldata = request.getParameter("data");
SAXReader sax=new SAXReader();//创建一个SAXReader对象
Document document=sax.read(new ByteArrayInputStream(xmldata.getBytes()));//获取document对象,如果文档无节点，则会抛出Exception提前结束
Element root=document.getRootElement();//获取根节点
List rowList = root.selectNodes("//msg");
Iterator<?> iter1 = rowList.iterator();
if (iter1.hasNext()) {
    Element beanNode = (Element) iter1.next();
    modelMap.put("success",true);
    modelMap.put("resp",beanNode.getTextTrim());
}
...
```
##### 审计函数
XML解析一般在导入配置、数据传输接口等场景可能会用到，涉及到XML文件处理的场景可留意下XML解析器是否禁用外部实体，从而判断是否存在XXE。部分XML解析接口如下：

```
javax.xml.parsers.DocumentBuilder
javax.xml.stream.XMLStreamReader
org.jdom.input.SAXBuilder
org.jdom2.input.SAXBuilder
javax.xml.parsers.SAXParser
org.dom4j.io.SAXReader 
org.xml.sax.XMLReader
javax.xml.transform.sax.SAXSource 
javax.xml.transform.TransformerFactory 
javax.xml.transform.sax.SAXTransformerFactory 
javax.xml.validation.SchemaFactory
javax.xml.bind.Unmarshaller
javax.xml.xpath.XPathExpression
...
```

##### 修复方案
使用XML解析器时需要设置其属性，禁止使用外部实体，以上例中SAXReader为例，安全的使用方式如下:

```
sax.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
sax.setFeature("http://xml.org/sax/features/external-general-entities", false);
sax.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
其它XML解析器的安全使用可参考[OWASP XML External Entity (XXE) Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#Java)

### 反序列化漏洞
##### 介绍
序列化是让 Java 对象脱离 Java 运行环境的一种手段，可以有效的实现多平台之间的通信、对象持久化存储。 

Java程序使用ObjectInputStream对象的readObject方法将反序列化数据转换为java对象。但当输入的反序列化的数据可被用户控制，那么攻击者即可通过构造恶意输入，让反序列化产生非预期的对象，在此过程中执行构造的任意代码。

##### 漏洞示例
漏洞代码示例如下：

``` java
......
//读取输入流,并转换对象
InputStream in=request.getInputStream();
ObjectInputStream ois = new ObjectInputStream(in);
//恢复对象
ois.readObject();
ois.close();
```
上述代码中，程序读取输入流并将其反序列化为对象。此时可查看项目工程中是否引入可利用的commons-collections 3.1、commons-fileupload 1.3.1等第三方库，即可构造特定反序列化对象实现任意代码执行。相关三方库及利用工具可参考ysoserial、marshalsec。
##### 审计函数
反序列化操作一般在导入模版文件、网络通信数据传输等业务场景,在代码审计时可重点关注一些反序列化操作函数，如下：

```	
ObjectInputStream.readObject
ObjectInputStream.readUnshared
XMLDecoder.readObject
Yaml.load
XStream.fromXML
ObjectMapper.readValue
JSON.parseObject
...
```
##### 修复方案
如果可以明确反序列化对象类的则可在反序列化时设置白名单，对于一些只提供接口的库则可使用黑名单设置不允许被反序列化类或者提供设置白名单的接口，可通过Hook函数resolveClass来校验反序列化的类从而实现白名单校验，示例如下：

```java
public class AntObjectInputStream extends ObjectInputStream{
    public AntObjectInputStream(InputStream inputStream)
            throws IOException {
        super(inputStream);
    }

    /**
     * 只允许反序列化SerialObject class
     */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException,
            ClassNotFoundException {
        if (!desc.getName().equals(SerialObject.class.getName())) {
            throw new InvalidClassException(
                    "Unauthorized deserialization attempt",
                    desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```
也可以使用Apache Commons IO Serialization包中的ValidatingObjectInputStream类的accept方法来实现反序列化类白/黑名单控制，如果使用的是第三方库则升级到最新版本。更多修复方案可参考[浅谈Java反序列化漏洞修复方案](https://xianzhi.aliyun.com/forum/topic/41/)。

### SSRF

##### 介绍
SSRF形成的原因大都是由于代码中提供了从其他服务器应用获取数据的功能但没有对目标地址做过滤与限制。比如从指定URL链接获取图片、下载等。

##### 漏洞示例
此处以HttpURLConnection为例，示例代码片段如下:

``` java
	String url = request.getParameter("picurl");
	StringBuffer response = new StringBuffer();

   	URL pic = new URL(url);
   	HttpURLConnection con = (HttpURLConnection) pic.openConnection();
	con.setRequestMethod("GET");
	con.setRequestProperty("User-Agent", "Mozilla/5.0");
	BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
	String inputLine;
	while ((inputLine = in.readLine()) != null) {
	     response.append(inputLine);
   	}
	in.close();
	modelMap.put("resp",response.toString());
	return "getimg.htm";
```

##### 审计函数
程序中发起HTTP请求操作一般在获取远程图片、页面分享收藏等业务场景,在代码审计时可重点关注一些HTTP请求操作函数，如下：

```	
HttpClient.execute
HttpClient.executeMethod
HttpURLConnection.connect
HttpURLConnection.getInputStream
URL.openStream
...
```
##### 修复方案

* 使用白名单校验HTTP请求url地址
* 避免将请求响应及错误信息返回给用户
* 禁用不需要的协议及限制请求端口,仅仅允许http和https请求等

### SQLi

##### 介绍
注入攻击的本质，是程序把用户输入的数据当做代码执行。这里有两个关键条件，第一是用户能够控制输入；第二是用户输入的数据被拼接到要执行的代码中从而被执行。sql注入漏洞则是程序将用户输入数据拼接到了sql语句中，从而攻击者即可构造、改变sql语义从而进行攻击。
##### 漏洞示例
此处以Mybatis框架为例，示例sql片段如下:

```sql
select * from books where id= ${id}
```
对于Mybatis框架下SQL注入漏洞的审计可参考[Mybatis框架下SQL注入漏洞面面观](https://mp.weixin.qq.com/s?__biz=MjM5OTk2MTMxOQ==&mid=2727827368&idx=1&sn=765d0835f0069b5145523c31e8229850&mpshare=1&scene=1&srcid=0926a6QC3pGbQ3Pznszb4n2q)

##### 修复方案

Mybatis框架SQL语句安全写法应使用\#\{\},避免使用动态拼接形式\$\{\}。安全写法如下:

```
select * from books where id= #{id}

```

### Autobinding
##### 介绍
Autobinding-自动绑定漏洞，根据不同语言/框架，该漏洞有几个不同的叫法，如下：

* Mass Assignment: Ruby on Rails, NodeJS
* Autobinding: Spring MVC, ASP.NET MVC
* Object injection: PHP(对象注入、反序列化漏洞)

软件框架有时允许开发人员自动将HTTP请求参数绑定到程序代码变量或对象中，从而使开发人员更容易地使用该框架。这里攻击者就可以利用这种方法通过构造http请求，将请求参数绑定到对象上，当代码逻辑使用该对象参数时就可能产生一些不可预料的结果。

##### 漏洞示例
示例代码以[ZeroNights-HackQuest-2016](https://github.com/GrrrDog/ZeroNights-HackQuest-2016)的demo为例，把示例中的justiceleague程序运行起来，可以看到这个应用菜单栏有about，reg，Sign up，Forgot password这4个页面组成。我们关注的点是密码找回功能，即怎么样绕过安全问题验证并找回密码。

1）首先看reset方法，把不影响代码逻辑的删掉。这样更简洁易懂：

```
@Controller
@SessionAttributes("user")
public class ResetPasswordController {

private UserService userService;
...
@RequestMapping(value = "/reset", method = RequestMethod.POST)
public String resetHandler(@RequestParam String username, Model model) {
		User user = userService.findByName(username);
		if (user == null) {
			return "reset";
		}
		model.addAttribute("user", user);
		return "redirect: resetQuestion";
	}
```
这里从参数获取username并检查有没有这个用户，如果有则把这个user对象放到Model中。因为这个Controller使用了@SessionAttributes("user")，所以同时也会自动把user对象放到session中。然后跳转到resetQuestion密码找回安全问题校验页面。

2）resetQuestion密码找回安全问题校验页面有resetViewQuestionHandler这个方法展现

```
@RequestMapping(value = "/resetQuestion", method = RequestMethod.GET)
	public String resetViewQuestionHandler(@ModelAttribute User user) {
		logger.info("Welcome resetQuestion ! " + user);
		return "resetQuestion";
	}
```
这里使用了@ModelAttribute User user，实际上这里是从session中获取user对象。但存在问题是如果在请求中添加user对象的成员变量时则会更改user对象对应成员的值。
所以当我们给resetQuestionHandler发送GET请求的时候可以添加“answer=hehe”参数，这样就可以给session中的对象赋值，将原本密码找回的安全问题答案修改成“hehe”。这样在最后一步校验安全问题时即可验证成功并找回密码

##### 审计函数
对于自动绑定漏洞重点留意几个注解如下：

```	
@SessionAttributes
@ModelAttribute
...
```
更多信息可参考[Spring MVC Autobinding漏洞实例初窥](https://xianzhi.aliyun.com/forum/topic/1089/)
##### 修复方案
Spring MVC中可以使用@InitBinder注解，通过WebDataBinder的方法setAllowedFields、setDisallowedFields设置允许或不允许绑定的参数。

### URL重定向

##### 介绍
由于Web站点有时需要根据不同的逻辑将用户引向到不同的页面，如典型的登录接口就经常需要在认证成功之后将用户引导到登录之前的页面，整个过程中如果实现不好就可能导致URL重定向问题，攻击者构造恶意跳转的链接，可以向用户发起钓鱼攻击。

##### 漏洞示例
此处以Servlet的redirect 方式为例，示例代码片段如下:

``` java
	String site = request.getParameter("url");
	if(!site.isEmpty()){
		response.sendRedirect(site);
	}
```

##### 审计函数
java程序中URL重定向的方法均可留意是否对跳转地址进行校验、重定向函数如下：

```	
sendRedirect
setHeader
forward
...
```
##### 修复方案

* 使用白名单校验重定向的url地址
* 给用户展示安全风险提示，并由用户再次确认是否跳转

### CSRF

##### 介绍
跨站请求伪造（Cross-Site Request Forgery，CSRF）是一种使已登录用户在不知情的情况下执行某种动作的攻击。因为攻击者看不到伪造请求的响应结果，所以CSRF攻击主要用来执行动作，而非窃取用户数据。当受害者是一个普通用户时，CSRF可以实现在其不知情的情况下转移用户资金、发送邮件等操作；但是如果受害者是一个具有管理员权限的用户时CSRF则可能威胁到整个Web系统的安全。

##### 漏洞示例
由于开发人员对CSRF的了解不足，错把“经过认证的浏览器发起的请求”当成“经过认证的用户发起的请求”，当已认证的用户点击攻击者构造的恶意链接后就“被”执行了相应的操作。例如，一个博客删除文章是通过如下方式实现的：

``` 
GET http://blog.com/article/delete.php?id=102
``` 

当攻击者诱导用户点击下面的链接时，如果该用户登录博客网站的凭证尚未过期，那么他便在不知情的情况下删除了id为102的文章，简单的身份验证只能保证请求发自某个用户的浏览器，却不能保证请求本身是用户自愿发出的。

##### 漏洞审计

此类漏洞一般都会在框架中解决修复，所以在审计csrf漏洞时。首先要熟悉框架对CSRF的防护方案，一般审计时可查看增删改请求重是否有token、formtoken等关键字以及是否有对请求的Referer有进行校验。手动测试时,如果有token等关键则替换token值为自定义值并重放请求，如果没有则替换请求Referer头为自定义链接或置空。重放请求看是否可以成功返回数据从而判断是否存在CSRF漏洞。

##### 修复方案
* Referer校验，对HTTP请求的Referer校验，如果请求Referer的地址不在允许的列表中，则拦截请求。
* Token校验，服务端生成随机token，并保存在本次会话cookie中，用户发起请求时附带token参数，服务端对该随机数进行校验。如果不正确则认为该请求为伪造请求拒绝该请求。
* Formtoken校验，Formtoken校验本身也是Token校验，只是在本次表单请求有效。
* 对于高安全性操作则可使用验证码、短信、密码等二次校验措施
* 增删改请求使用POST请求

### 命令执行
##### 介绍
由于业务需求，程序有可能要执行系统命令的功能，但如果执行的命令用户可控，业务上有没有做好限制，就可能出现命令执行漏洞。

##### 漏洞示例
此处以getRuntime为例，示例代码片段如下:

``` java
	String cmd = request.getParameter("cmd");
	Runtime.getRuntime().exec(cmd);
```

##### 审计函数
这种漏洞原理上很简单，重点是找到执行系统命令的函数，看命令是否可控。在一些特殊的业务场景是能判断出是否存在此类功能，这里举个典型的实例场景,有的程序功能需求提供网页截图功能，笔者见过多数是使用phantomjs实现，那势必是需要调用系统命令执行phantomjs并传参实现截图。而参数大多数情况下应该是当前url或其中获取相关参数，此时很有可能存在命令执行漏洞，还有一些其它比较特别的场景可自行脑洞。

java程序中执行系统命令的函数如下：

```	
Runtime.exec
ProcessBuilder.start
GroovyShell.evaluate
...
```
##### 修复方案

* 避免命令用户可控
* 如需用户输入参数，则对用户输入做严格校验

### 权限控制
##### 介绍
越权漏洞可以分为水平、垂直越权两种,程序在处理用户请求时未对用户的权限进行校验，使的用户可访问、操作其他相同角色用户的数据，这种情况是水平越权；如果低权限用户可访问、操作高权限用户则的数据，这种情况为垂直越权。

##### 漏洞示例

``` java
	@RequestMapping(value="/getUserInfo",method = RequestMethod.GET)
    public String getUserInfo(Model model, HttpServletRequest request) throws IOException {
        String userid = request.getParameter("userid");
        if(!userid.isEmpty()){
            String info=userModel.getuserInfoByid(userid);
            return info;
        }
        return "";
    }
```

##### 审计函数
水平、垂直越权不需关注特定函数，只要在处理用户操作请求时查看是否有对当前登陆用户权限做校验从而确定是否存在漏洞
##### 修复方案
获取当前登陆用户并校验该用户是否具有当前操作权限，并校验请求操作数据是否属于当前登陆用户，当前登陆用户标识不能从用户可控的请求参数中获取。

### 请求轰炸
##### 介绍
业务中经常会有使用到发送短信校验码、短信通知、邮件通知等一些功能，这类请求如果不做任何限制，恶意攻击者可能进行批量恶意请求轰炸，大量短信、邮件等通知对正常用户造成困扰，同时也是对公司的资源造成损耗。

##### 修复方案
* 对同一个用户发起这类请求的频率、每小时及每天发送量在服务端做限制，不可在前端实现限制

### 待续...

### 总结
除了上述相关的漏洞，在代码审计的时候有时会遇到一些特别的漏洞，比如开发为了测试方便关闭掉了一些安全校验函数、甚至未彻底清除的一些预留后门及测试管理接口等。逻辑相关的漏洞则要熟悉应用本身的设计和逻辑。除此，框架本身的安全问题也是可以深挖。一些安全校验、安全解决方案也未必就毫无破绽的。

