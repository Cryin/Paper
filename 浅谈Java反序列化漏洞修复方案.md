## 浅谈Java反序列化漏洞修复方案

### 概述
序列化是让 Java 对象脱离 Java 运行环境的一种手段，可以有效的实现多平台之间的通信、对象持久化存储。 

Java程序使用ObjectInputStream对象的readObject方法将反序列化数据转换为java对象。但当输入的反序列化的数据可被用户控制，那么攻击者即可通过构造恶意输入，让反序列化产生非预期的对象，在此过程中执行构造的任意代码。

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
安全研究人员已经发现大量利用反序列化漏洞执行任意代码的方法，Gabriel Lawrence和Chris Frohoff在《[Marshalling Pickles how deserializing objects can ruin your day](https://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)》中提出的利用Apache Commons Collection实现任意代码执行，还有其它更多的利用方法可参考github上的利用工具[ysoserial](https://github.com/frohoff/ysoserial)、[marshalsec](https://github.com/mbechler/marshalsec)。

### Java反序列化详解
#### 序列化数据结构
通过查看序列化后的数据，可以看到反序列化数据开头包含两字节的魔术数字，这两个字节始终为十六进制的0xAC ED。接下来是两字节的版本号0x00 05的数据。此外还包含了类名、成员变量的类型和个数等。详细可参考[Java对象序列化规范](https://docs.oracle.com/javase/7/docs/platform/serialization/spec/protocol.html)。

这里以类SerialObject示例来详细进行介绍Java对象序列化后的数据结构：

``` java
public class SerialObject implements Serializable{
    private static final long serialVersionUID = 5754104541168322017L;

    private int id;
    public String name;

    public SerialObject(int id,String name){
        this.id=id;
        this.name=name;
    }
    ...
}
```

序列化SerialObject实例后以二进制格式查看：

```
00000000: aced 0005 7372 0024 636f 6d2e 7878 7878  ....sr.$com.xxxx
00000010: 7878 2e73 6563 2e77 6562 2e68 6f6d 652e  xx.sec.web.home.
00000020: 5365 7269 616c 4f62 6a65 6374 4fda af97  SerialObjectO...
00000030: f8cc c5e1 0200 0249 0002 6964 4c00 046e  .......I..idL..n
00000040: 616d 6574 0012 4c6a 6176 612f 6c61 6e67  amet..Ljava/lang
00000050: 2f53 7472 696e 673b 7870 0000 07e1 7400  /String;xp....t.
00000060: 0563 7279 696e 0a                        .cryin.
```

序列化的数据流以魔术数字和版本号开头，这个值是在调用ObjectOutputStream序列化时，由writeStreamHeader方法写入：

```java
protected void writeStreamHeader() throws IOException {
     bout.writeShort(STREAM_MAGIC);//STREAM_MAGIC (2 bytes) 0xACED
     bout.writeShort(STREAM_VERSION);//STREAM_VERSION (2 bytes) 5
    }
```

序列化后的SerialObject对象详细结构：

```
STREAM_MAGIC (2 bytes) 0xACED 
STREAM_VERSION (2 bytes) 0x0005
    TC_OBJECT (1 byte) 0x73
        TC_CLASSDESC (1 byte) 0x72
        className
            length (2 bytes) 0x24 = 36
            text (36 bytes) com.xxxxxx.sec.web.home.SerialObject
        serialVersionUID (8 bytes) 0x4FDAAF97F8CCC5E1 = 5754104541168322017
        classDescInfo
            classDescFlags (1 byte) 0x02 = SC_SERIALIZABLE
            fields
                count (2 bytes) 2
                field[0]
                    primitiveDesc
                        prim_typecode (1 byte) I = integer
                        fieldName
                            length (2 bytes) 2
                            text (2 bytes) id
                field[1]
                    objectDesc
                        obj_typecode (1 byte) L = object
                        fieldName
                            length (2 bytes) 4
                            text (4 bytes)  name
                        className1
                            TC_STRING (1 byte) 0x74
                                length (2 bytes) 0x12 = 18
                                text (18 bytes) Ljava/lang/String;
 
            classAnnotation
                TC_ENDBLOCKDATA (1 byte) 0x78
 
            superClassDesc
                TC_NULL (1 byte) 0x70
    classdata[]
        classdata[0] (4 bytes) 0xe107 = id = 2017
        classdata[1]
            TC_STRING (1 byte) 0x74
            length (2 bytes) 5
            text (8 bytes) cryin
```

#### 反序列化过程
Java程序中类ObjectInputStream的readObject方法被用来将数据流反序列化为对象，如果流中的对象是class，则它的ObjectStreamClass描述符会被读取，并返回相应的class对象，ObjectStreamClass包含了类的名称及serialVersionUID。

如果类描述符是动态代理类，则调用resolveProxyClass方法来获取本地类。如果不是动态代理类则调用resolveClass方法来获取本地类。如果无法解析该类，则抛出ClassNotFoundException异常。

如果反序列化对象不是String、array、enum类型，ObjectStreamClass包含的类会在本地被检索，如果这个本地类没有实现java.io.Serializable或者externalizable接口，则抛出InvalidClassException异常。因为只有实现了Serializable和Externalizable接口的类的对象才能被序列化。

### Java反序列化漏洞修复方案
#### 通过Hook resolveClass来校验反序列化的类
通过上面序列化数据结构可以了解到包含了类的名称及serialVersionUID的ObjectStreamClass描述符在序列化对象流的前面位置，且在readObject反序列化时首先会调用resolveClass读取反序列化的类名，所以这里通过重写ObjectInputStream对象的resolveClass方法即可实现对反序列化类的校验。这个方法最早是由IBM的研究人员Pierre Ernst在2013年提出《[Look-ahead Java deserialization](https://www.ibm.com/developerworks/library/se-lookahead/)》，具体实现代码示例如下:

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
通过此方法，可灵活的设置允许反序列化类的白名单，也可设置不允许反序列化类的黑名单。但反序列化漏洞利用方法一直在不断的被发现，黑名单需要一直更新维护，且未公开的利用方法无法覆盖。

[SerialKiller](https://github.com/ikkisoft/SerialKiller) 是由Luca Carettoni利用上面介绍的方法实现的反序列化类白/黑名单校验的jar包。具体使用方法可参考其代码仓库。

#### 使用ValidatingObjectInputStream来校验反序列化的类
使用Apache Commons IO Serialization包中的ValidatingObjectInputStream类的accept方法来实现反序列化类白/黑名单控制，具体可参考[ValidatingObjectInputStream](https://commons.apache.org/proper/commons-io/javadocs/api-release/index.html)介绍；示例代码如下:

```java
private static Object deserialize(byte[] buffer) throws IOException,
ClassNotFoundException , ConfigurationException {
	Object obj;
	ByteArrayInputStream bais = new ByteArrayInputStream(buffer);
	// Use ValidatingObjectInputStream instead of InputStream
	ValidatingObjectInputStream ois = new 	ValidatingObjectInputStream(bais); 

	//只允许反序列化SerialObject class
	ois.accept(SerialObject.class);
	obj = ois.readObject();
	return obj;
}
```
#### 使用contrast-rO0防御反序列化攻击
[contrast-rO0](https://github.com/Contrast-Security-OSS/contrast-rO0)是一个轻量级的agent程序，通过通过重写ObjectInputStream来防御反序列化漏洞攻击。使用其中的SafeObjectInputStream类来实现反序列化类白/黑名单控制，示例代码如下:

```java
SafeObjectInputStream in = new SafeObjectInputStream(inputStream, true);
in.addToWhitelist(SerialObject.class);

in.readObject();
```
#### 使用ObjectInputFilter来校验反序列化的类

Java 9包含了支持序列化数据过滤的新特性，开发人员也可以继承[java.io.ObjectInputFilter](http://download.java.net/java/jdk9/docs/api/java/io/ObjectInputFilter.html)类重写checkInput方法实现自定义的过滤器，，并使用ObjectInputStream对象的[setObjectInputFilter](http://download.java.net/java/jdk9/docs/api/java/io/ObjectInputStream.html#setObjectInputFilter-java.io.ObjectInputFilter-)设置过滤器来实现反序列化类白/黑名单控制。示例代码如下:

```java
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.io.ObjectInputFilter;
class BikeFilter implements ObjectInputFilter {
	private long maxStreamBytes = 78; // Maximum allowed bytes in the stream.
	private long maxDepth = 1; // Maximum depth of the graph allowed.
	private long maxReferences = 1; // Maximum number of references in a graph.
	@Override
	public Status checkInput(FilterInfo filterInfo) {
		if (filterInfo.references() < 0 || filterInfo.depth() < 0 || filterInfo.streamBytes() < 0 || filterInfo.references() > maxReferences || filterInfo.depth() > maxDepth|| filterInfo.streamBytes() > maxStreamBytes) {
			return Status.REJECTED;
		}
		Class<?> clazz = filterInfo.serialClass();
		if (clazz != null) {
			if (SerialObject.class == filterInfo.serialClass()) {
				return Status.ALLOWED;
			}
			else {
				return Status.REJECTED;
			}
		}
		return Status.UNDECIDED;
	} // end checkInput
} // end class BikeFilter
```
上述示例代码，仅允许反序列化SerialObject类对象，上述示例及更多关于ObjectInputFilter的均参考自NCC Group Whitepaper由Robert C. Seacord写的《[Combating Java Deserialization
Vulnerabilities with Look-Ahead Object
Input Streams (LAOIS)](https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/2017/june/ncc_group_combating_java_deserialization_vulnerabilities_with_look-ahead_object_input_streams1.pdf)》

#### 黑名单

在反序列化时设置类的黑名单来防御反序列化漏洞利用及攻击，这个做法在源代码修复的时候并不是推荐的方法，因为你不能保证能覆盖所有可能的类，而且有新的利用payload出来时也需要随之更新黑名单，但有一种场景下可能黑名单是一个不错的选择。写代码的时候总会把一些经常用到的方法封装到公共类，这样其它工程中用到只需要导入jar包即可，此前已经见到很多提供反序列化操作的公共接口，使用第三方库反序列化接口就不好用白名单的方式来修复了。这个时候作为第三方库也不知道谁会调用接口，会反序列化什么类，所以这个时候可以使用黑名单的方式来禁止一些已知危险的类被反序列化，具体的黑名单类可参考contrast-rO0、ysoserial中paylaod包含的类。

### 总结
前段时间对反序列化漏洞的检测和修复进行了专项的研究，刚好又看到NCC Group关于反序列化漏洞研究的[Whitepaper](https://www.nccgroup.trust/us/our-research/combating-java-deserialization-vulnerabilities-with-look-ahead-object-input-streams-laois/)。所以对反序列化漏洞的原理、检测和修复进行大概的整理，漏洞修复方案主要趋向于有源代码的情况。文中若有问题之处可指出再交流。

### 参考

* https://www.nccgroup.trust/us/our-research/combating-java-deserialization-vulnerabilities-with-look-ahead-object-input-streams-laois/
* https://github.com/ikkisoft/SerialKiller/
* https://github.com/Contrast-Security-OSS/contrast-rO0
* https://dzone.com/articles/a-first-look-into-javas-new-serialization-filterin
* https://docs.oracle.com/javase/7/docs/platform/serialization/spec/protocol.html
* https://www.owasp.org/index.php/Deserialization_of_untrusted_data
* https://github.com/Cryin/Paper/blob/master/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%E5%8F%8A%E6%A3%80%E6%B5%8B%E6%96%B9%E6%A1%88.md
* https://www.ibm.com/developerworks/library/se-lookahead/

