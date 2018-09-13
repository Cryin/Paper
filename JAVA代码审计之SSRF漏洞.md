### JAVA代码审计之SSRF漏洞

#### 概述
SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。因为它是由服务端发起的，所以它能够请求到与它相连而与外网隔离的内部服务器系统

SSRF形成的原因大都是由于代码中提供了从其他服务器应用获取数据的功能但没有对目标地址做过滤与限制。常见的场景比如：
* 从指定URL链接获取内容、下载
* 端口开放检测
* 数据源连接
* 读片读取
* 接口调用测试
* 后台状态刷新
* 代码库clone等操作
* web hook消息同步等

本文从java代码审计出发，对ssrf漏洞的审计和常见场景进行介绍。

#### 常见场景及案例

* 使用HttpURLConnection发起HTTP请求获取响应信息，代码示例如下：
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
* 使用httpClient获取图片二进制流，代码示例如下：
``` java
  CloseableHttpClient httpClient = HttpClients.createDefault();
  HttpGet getRequest = new HttpGet(url);
  HttpResponse response = httpClient.execute(getRequest);
  if(response.getStatusLine().getStatusCode() == 200)
    {
        HttpEntity entity = response.getEntity();
        return EntityUtils.toByteArray(entity);
    }
  throw new IOException("Error:下载图片失败");
```

* 使用Socket建立链接判断ip对应端口的联通性，代码示例如下：
``` java
  String host = request.getParameter("host");
  String port = request.getParameter("port");
  Socket socket = null;
  try {
        socket = new Socket(host, port);
        return true;
      } catch (Exception e) {
          logger.error("connect test failed!", e);
          return false;
      } finally {
        if (socket != null) {
            try {
                  socket.close();
            } catch (IOException e) {
                  logger.error("Socket close error!", e);
            }
          }
      }
```
* 使用OkHttpClient发起http请求，代码示例如下：
``` java
  String url = request.getParameter("url");
  OkHttpClient httpClient = new OkHttpClient();
  Request request = new Request.Builder()
        .url(url)
        .build();
  Response response = httpClient.newCall(request).execute();
  return response.body().string(); 
```
* 使用ImageIO读取远程图片，代码示例如下：
``` java
  String imgurl = request.getParameter("url");
  URL url = new URL(imgurl);
  Image image = ImageIO.read(url);
  return image; 
```
* mysql等数据源连接，代码示例如下：
``` java
public boolean connection(String url, String username,String passwd) {
        DataSource mysqlDataSource = getDataSourceByDriver("com.mysql.jdbc.Driver", username, passwd, url);
        Connection conn = null;
        try {
            conn = mysqlDataSource.getConnection();
            if (conn == null) return false;
            return true;
        } catch (SQLException e) {
            logger.error("mysql Connect failed! url:" + url, e);
            handleSQLException(e);
        } 
        return false;
    }
```
#### SSRF漏洞修复方案
* 避免请求url外部可控
* 避免将请求响应及错误信息返回给用户
* 使用白名单校验请求url及ip地址
* 禁用不需要的协议及限制请求端口,仅允许http和https请求等
* host及端口固定，path外部可控可通过@绕过，也要做白名单校验
