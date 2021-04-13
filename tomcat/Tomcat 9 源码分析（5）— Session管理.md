# Session管理



Session可以用来管理用户的会话信息，最常见的就是拿Session来存放用户登录、身份、权限及状态等信息。对于使用Tomcat作为Web容器的大部分开发人员而言，本文介绍分析Tomcat是如何实现Session标记用户和管理Session信息



## Session接口



Tomcat内部定义了**Session**和**HttpSession**这两个会话相关的接口，其类继承体系如下



![avator][SessionInterface]

**Session**：Tomcat中有关会话的基本接口规范，下面介绍它定义的主要方法

| 方法                                | 描述                        |
| ----------------------------------- | :-------------------------- |
| getCreationTime()/setCreationTime() | 获取与设置Session的创建时间 |
| getId()/setId()                     | 获取与设置Session的ID       |
| getThisAccessedTime()               | 获取最近一次请求的开始时间  |
| getLastAccessedTime()               | 获取最近一次请求的完成时间  |
| getManager()/setManager()           | 获取与设置Session管理器     |
| getMaxInactiveInterval()            | 获取Session的最大访问间隔   |
| setMaxInactiveInterval()            | 设置Session的最大访问间隔   |
| getSession()                        | 获取HttpSession             |
| setValid()/isValid()                | 获取与设置Session的有效状态 |
| access()/endAccess()                | 开始与结束Session的访问     |
| expire()                            | 设置Session过期             |



**HttpSession**：在HTTP客户端与HTTP服务端提供的一种会话的接口规范

| 方法                          | 描述                                             |
| ----------------------------- | ------------------------------------------------ |
| getCreationTime()             | 获取Session的创建时间                            |
| getId()                       | 获取Session的ID                                  |
| getLastAccessedTime()         | 获取最近一次请求的完成时间                       |
| getServletContext()           | 获取当前Session所属的ServletContext              |
| getMaxInactiveInterval()      | 获取Session的最大访问间隔                        |
| setMaxInactiveInterval()      | 设置Session的最大访问间隔                        |
| getAttribute()/setAttribute() | 获取与设置Session作用域的属性                    |
| removeAttribute()             | 清除Session作用域的属性                          |
| invalidate()                  | 使Session失效并解除任何与此Session绑定的    对象 |



**ClusterSession**：集群部署下的会话接口规范

| 方法                | 描述                      |
| ------------------- | ------------------------- |
| isPrimarySession()  | 判断是否为集群的主Session |
| setPrimarySession() | 设置集群主Session         |



**StandardSession**：标准的HTTP Session实现，本文将以此实现为例展开

**DeltaSession**：Tomcat集群会话同步的策略，对会话中增量修改的属性进行同步。这种方式由于是增量的，所以会大大降低网络I/O的开销，但是是线上会比较复杂因为涉及到对会话属性操作过程的管理

**ReplicationSessionListener**：Tomcat集群会话同步的策略，每次都会把整个会话对象同步给集群中的其他节点，其他节点然后更新整个会话对象。这种实现比较简单但会造成大量无效信息的传输



## Session管理器



Tomcat内部定义了Manager接口用于制定Session管理器的接口规范，目前已经有很多Session管理器的实现

![avator][SessionManager]



**Manager**：Tomcat对于Session管理器定义的接口规范

| 方法                           | 描述                                                         |
| ------------------------------ | ------------------------------------------------------------ |
| getContext()/setContext()      | 获取与设置上下文                                             |
| getSessionIdGenerator()        | 获取会话id生成器                                             |
| setSessionIdGenerator()        | 设置会话id生成器                                             |
| getSessionCounter()            | 获取Session计数器                                            |
| setSessionCounter()            | 设置Session计数器                                            |
| getMaxActive()/setMaxActive()  | 获取与设置处于活动状态的最大会话数                           |
| getActiveSessions()            | 获取处于活跃状态的会话数                                     |
| getExpiredSessions()           | 获取过期的会话数                                             |
| setExpiredSessions()           | 设置过期的会话数                                             |
| getRejectedSessions()          | 获取未创建的会话数                                           |
| getSessionMaxAliveTime()       | 获取会话存活的最长时间（单位为秒）                           |
| setSessionMaxAliveTime()       | 设置会话存活的最长时间（单位为秒）                           |
| getSessionAverageAliveTime()   | 获取会话平均存活时间                                         |
| getSessionCreateRate()         | 获取当前会话创建速率                                         |
| getSessionExpireRate()         | 获取当前会话过期速率                                         |
| add()                          | 将此会话添加到处于活动状态的会话集合                         |
| addPropertyChangeListener()    | 将属性更改监听器到此组件                                     |
| changeSessionId()              | 将当前会话的ID更改为新的随机生成的会话ID                     |
| rotateSessionId()              | 将当前会话的ID更改为新的随机生成的会话ID                     |
| changeSessionId()              | 将当前会话的ID更改为指定的会话ID                             |
| createEmptySession()           | 从回收的会话中获取会话或创建一个新的会话                     |
| createSession()                | 根据默认值构造并返回一个新的会话对象                         |
| findSession()                  | 返回与此管理器关联的会话                                     |
| findSessions()                 | 返回与此管理器关联的会话集合                                 |
| load()/unload()                | 从持久化机制中加载Session或向持久化机制写入Session           |
| remove()                       | 从此管理器的活动会话中删除此会话                             |
| removePropertyChangeListener() | 从此组件中删除属性更改监听器                                 |
| backgroundProcess()            | 容器接口中定义为具体容器在后台处理相关工作的实现，Session管理器基于此机制实现了过期Session的 |
| willAttributeDistribute()      | 管理器写入指定的会话属性                                     |



**ManagerBase**：封装了Manager接口通用实现的抽象类，未提供对load()/unload()等方法的实现，需要具体子类去实现。所有的Session管理器都集成自ManagerBase

**ClusterManager**：在Manager接口的基础上增加了集群部署下的一些接口，所有实现集群下Session管理器都要实现此接口

**PersistentManagerBase**：提供了对于Session持久化的基本实现

**PersistentManager**：继承自PersistentManagerBase，可以在Server.xml的<Context>元素下通过配置<Store>元素来使用。PersistentManager可以将内存中的Session信息备份到文件或数据库中。当备份一个Session对象时，该Session对象会被复制到存储器（文件或者数据库）中，而原对象仍然留在内存中。因此即便服务器宕机，仍然可以从存储器中获取活动的Session对象。如果活动的Session对象超过了上限值或者Session对象闲置了的时间过长，那么Session会被换出到存储器中以节省内存空间

**StandardManager**：不用配置<Store>元素，当Tomcat正常关闭，重启或Web应用重新加载时，它会将内存中的Session序列化到Tomcat目录的`/work/Catalina/host_name/webapp_name/SESSIONS.ser`文件中。当Tomcat重启或者应用加载完成后，Tomcat会将文件中的Session重新还原到内存中。如果突然中止该服务器，则所有Session豆浆丢失，因为StandardManager没有机会实现存盘处理

**ClusterManagerBase**：提供了对于Session的集群管理实现

**DeltaManager**：继承自ClusterManagerBase。此Session管理器是Tomcat集群部署下的默认管理器，当集群中的某一节点生成或修改Session后，DeltaManager将会把这些修改增量复制到其他节点

**BackupManager**：没有继承ClusterManagerBase，而是直接实现了ClusterManager接口。是Tomcat在集群部署下的可选的Session管理器，集群中的所有Session都被全量复制到一个备份节点。集群中的所有节点都可以访问此备份节点，达到Session在集群下的备份效果



本文以StandardManager为例讲解Session的管理。StandardManager是StandardContext的子组件，用来管理当前Context的所有Session的创建和维护。由Tomcat生命周期管理可知，当StandardContext正式启动，也就是StandardContext的startInternal方法被调用时，StandardContext还会启动StandardManager



> org.apache.catalina.core.StandardContext.startInternal()

```java
@Override
protected synchronized void startInternal() throws LifecycleException {

    // 省略与Session管理无关的代码

            // Acquire clustered manager
            Manager contextManager = null;
            Manager manager = getManager();
            if (manager == null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("standardContext.cluster.noManager",
                            Boolean.valueOf((getCluster() != null)),
                            Boolean.valueOf(distributable)));
                }
                if ((getCluster() != null) && distributable) {
                    try {
                        contextManager = getCluster().createManager(getName());
                    } catch (Exception ex) {
                        log.error(sm.getString("standardContext.cluster.managerError"), ex);
                        ok = false;
                    }
                } else {
                    contextManager = new StandardManager();
                }
            }

            // Configure default manager if none was specified
            if (contextManager != null) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("standardContext.manager",
                            contextManager.getClass().getName()));
                }
                setManager(contextManager);
            }

            if (manager!=null && (getCluster() != null) && distributable) {
                //let the cluster know that there is a context that is distributable
                //and that it has its own manager
                getCluster().registerManager(manager);
            }
        }

       // 省略与Session管理无关的代码

        try {
            // Start manager
            Manager manager = getManager();
            if (manager instanceof Lifecycle) {
                ((Lifecycle) manager).start();
            }
        } catch(Exception e) {
            log.error(sm.getString("standardContext.managerFail"), e);
            ok = false;
        }

        // 省略与Session管理无关的代码
}
```





从中可知`StandardContext.startInternal()`中涉及Session管理的执行步骤如下：

1. 创建StandardManager
2. 如果Tomcat结合Apache做了分布式部署，会将当前StandardManager注册到集群中
3. 启动StandardManager



`StandardManger.start()`用于启动StandardManager



> org.apache.catalina.util.LifecycleBase.start()

```java
@Override
public final synchronized void start() throws LifecycleException {

    // 省略状态校验的代码

    if (state.equals(LifecycleState.NEW)) {
        init();
    } else if (state.equals(LifecycleState.FAILED)) {
        stop();
    } else if (!state.equals(LifecycleState.INITIALIZED) &&
            !state.equals(LifecycleState.STOPPED)) {
        invalidTransition(Lifecycle.BEFORE_START_EVENT);
    }

    try {
        setStateInternal(LifecycleState.STARTING_PREP, null, false);
        startInternal();
        if (state.equals(LifecycleState.FAILED)) {
            // This is a 'controlled' failure. The component put itself into the
            // FAILED state so call stop() to complete the clean-up.
            stop();
        } else if (!state.equals(LifecycleState.STARTING)) {
            // Shouldn't be necessary but acts as a check that sub-classes are
            // doing what they are supposed to.
            invalidTransition(Lifecycle.AFTER_START_EVENT);
        } else {
            setStateInternal(LifecycleState.STARTED, null, false);
        }
    } catch (Throwable t) {
        // This is an 'uncontrolled' failure so put the component into the
        // FAILED state and throw an exception.
        handleSubClassException(t, "lifecycleBase.startFail", toString());
    }
}
```



从中可知启动StandardManager的步骤如下：

1. 调用init方法初始化StandardManager
2. 调用startInternal方法启动StandardManager



### StandardManager的初始化

经上分析可知，启动StandardManager的第一部就是调用父类LifecycleBase的init方法，init方法在Tomcat生命周期管理中已介绍，现在只需要关心StandardManager的initInternal。StandardManager本身并没有实现initInternal方法，但是StandardManager的父类ManagerBase实现了此方法，将StandardManager注册为到 JMX



> org.apache.catalina.session.ManagerBase.initInternal()

```java
@Override
protected void initInternal() throws LifecycleException {
    super.initInternal();

    if (context == null) {
        throw new LifecycleException(sm.getString("managerBase.contextNull"));
    }
}
```



### StandardManager的启动

调用StandardManager的startInternal方法用于启动StandardManager



> org.apache.catalina.session.StandardManager.startInternal()

```java
@Override
protected synchronized void startInternal() throws LifecycleException {

    super.startInternal();

    // Load unloaded sessions, if any
    try {
        load();
    } catch (Throwable t) {
        ExceptionUtils.handleThrowable(t);
        log.error(sm.getString("standardManager.managerLoad"), t);
    }

    setState(LifecycleState.STARTING);
}

```



> org.apache.catalina.session.ManagerBase.startInternal()

```java
@Override
protected void startInternal() throws LifecycleException {

    // Ensure caches for timing stats are the right size by filling with
    // nulls.
    while (sessionCreationTiming.size() < TIMING_STATS_CACHE_SIZE) {
        sessionCreationTiming.add(null);
    }
    while (sessionExpirationTiming.size() < TIMING_STATS_CACHE_SIZE) {
        sessionExpirationTiming.add(null);
    }

    /* Create sessionIdGenerator if not explicitly configured */
    SessionIdGenerator sessionIdGenerator = getSessionIdGenerator();
    if (sessionIdGenerator == null) {
        sessionIdGenerator = new StandardSessionIdGenerator();
        setSessionIdGenerator(sessionIdGenerator);
    }

    sessionIdGenerator.setJvmRoute(getJvmRoute());
    if (sessionIdGenerator instanceof SessionIdGeneratorBase) {
        SessionIdGeneratorBase sig = (SessionIdGeneratorBase)sessionIdGenerator;
        sig.setSecureRandomAlgorithm(getSecureRandomAlgorithm());
        sig.setSecureRandomClass(getSecureRandomClass());
        sig.setSecureRandomProvider(getSecureRandomProvider());
    }

    if (sessionIdGenerator instanceof Lifecycle) {
        ((Lifecycle) sessionIdGenerator).start();
    } else {
        // Force initialization of the random number generator
        if (log.isDebugEnabled())
            log.debug("Force random number initialization starting");
        sessionIdGenerator.generateSessionId();
        if (log.isDebugEnabled())
            log.debug("Force random number initialization completed");
    }
}
```



StandardManager的startInternal首先调用了父类的startInternal方法，其内调generateSessionId方法初始化随机数生成器。然后加载持久化的Session信息，由于StandardManager中，所有的Session都维护在一个ConcurrentHashMap中，因此服务器重启或者宕机会造成这些Session信息丢失或失效，为了解决这个问题，Tomcat将这些Session通过持久化的方式来保证不会丢失。下面分析StandardManager的load方法实现



> org.apache.catalina.session.StandardManager.load()

```java
@Override
public void load() throws ClassNotFoundException, IOException {
    if (SecurityUtil.isPackageProtectionEnabled()){
        try{
            AccessController.doPrivileged( new PrivilegedDoLoad() );
        } catch (PrivilegedActionException ex){
            Exception exception = ex.getException();
            if (exception instanceof ClassNotFoundException) {
                throw (ClassNotFoundException)exception;
            } else if (exception instanceof IOException) {
                throw (IOException)exception;
            }
            if (log.isDebugEnabled()) {
                log.debug("Unreported exception in load() ", exception);
            }
        }
    } else {
        doLoad();
    }
}
```



> org.apache.catalina.session.StandardManager.PrivilegedDoLoad

```java
private class PrivilegedDoLoad
    implements PrivilegedExceptionAction<Void> {

    PrivilegedDoLoad() {
        // NOOP
    }

    @Override
    public Void run() throws Exception{
       doLoad();
       return null;
    }
}
```



否则调用实际负责加载的方法doLoad，而加载Session信息的方法也是doLoad



> org.apache.catalina.session.StandardManager.doLoad()

```java
protected void doLoad() throws ClassNotFoundException, IOException {
    if (log.isDebugEnabled()) {
        log.debug("Start: Loading persisted sessions");
    }

    // Initialize our internal data structures
    sessions.clear();

    // Open an input stream to the specified pathname, if any
    File file = file();
    if (file == null) {
        return;
    }
    if (log.isDebugEnabled()) {
        log.debug(sm.getString("standardManager.loading", pathname));
    }
    Loader loader = null;
    ClassLoader classLoader = null;
    Log logger = null;
    try (FileInputStream fis = new FileInputStream(file.getAbsolutePath());
            BufferedInputStream bis = new BufferedInputStream(fis)) {
        Context c = getContext();
        loader = c.getLoader();
        logger = c.getLogger();
        if (loader != null) {
            classLoader = loader.getClassLoader();
        }
        if (classLoader == null) {
            classLoader = getClass().getClassLoader();
        }

        // Load the previously unloaded active sessions
        synchronized (sessions) {
            try (ObjectInputStream ois = new CustomObjectInputStream(bis, classLoader, logger,
                    getSessionAttributeValueClassNamePattern(),
                    getWarnOnSessionAttributeFilterFailure())) {
                Integer count = (Integer) ois.readObject();
                int n = count.intValue();
                if (log.isDebugEnabled())
                    log.debug("Loading " + n + " persisted sessions");
                for (int i = 0; i < n; i++) {
                    StandardSession session = getNewSession();
                    session.readObjectData(ois);
                    session.setManager(this);
                    sessions.put(session.getIdInternal(), session);
                    session.activate();
                    if (!session.isValidInternal()) {
                        // If session is already invalid,
                        // expire session to prevent memory leak.
                        session.setValid(true);
                        session.expire();
                    }
                    sessionCounter++;
                }
            } finally {
                // Delete the persistent storage file
                if (file.exists()) {
                    if (!file.delete()) {
                        log.warn(sm.getString("standardManager.deletePersistedFileFail", file));
                    }
                }
            }
        }
    } catch (FileNotFoundException e) {
        if (log.isDebugEnabled()) {
            log.debug("No persisted data file found");
        }
        return;
    }

    if (log.isDebugEnabled()) {
        log.debug("Finish: Loading persisted sessions");
    }
}
```



分析可知，StandarManager的doLoad方法执行步骤如下：

1. 清空sessions缓存维护的Session信息
2. 调用file方法返回当前Context下的Session持久化文件
3. 打开Session持久化文件的输入流，并封装为CustomObjectInputStream
4. 从Session持久化文件读入持久化的Session的数量，然后逐个读取Session信息并放入到sessions缓存中



至此StandardManager的启动到此完成



## Session分配



在Tomcat请求原理分析中已经介绍了Filter的职责链，Tomcat接收到的请求会经过Filter职责链，最后交给具体的Servlet处理。以访问http://localhost:8080/host-manager这个路径为例，可以清楚的看到整个调用栈中Filter的职责链以及之后的JspServlet，最后到达`org.apache.catalina.connector.Request.getSession()`



Request的getSession方法用于获取当前请求对应的会话信息，如果没有则创建一个新的Session



> org.apache.catalina.connector.Request.getSession()

```java
@Override
public HttpSession getSession(boolean create) {
    Session session = doGetSession(create);
    if (session == null) {
        return null;
    }

    return session.getSession();
}
```



doGetSession方法的实现如下



> org.apache.catalina.connector.Request.doGetSession()

```java
protected Session doGetSession(boolean create) {

    // There cannot be a session if no context has been assigned yet
    Context context = getContext();
    if (context == null) {
        return null;
    }

    // Return the current session if it exists and is valid
    if ((session != null) && !session.isValid()) {
        session = null;
    }
    if (session != null) {
        return session;
    }

    // Return the requested session if it exists and is valid
    Manager manager = context.getManager();
    if (manager == null) {
        return null;      // Sessions are not supported
    }
    if (requestedSessionId != null) {
        try {
            session = manager.findSession(requestedSessionId);
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("request.session.failed", requestedSessionId, e.getMessage()), e);
            } else {
                log.info(sm.getString("request.session.failed", requestedSessionId, e.getMessage()));
            }
            session = null;
        }
        if ((session != null) && !session.isValid()) {
            session = null;
        }
        if (session != null) {
            session.access();
            return session;
        }
    }

    // Create a new session if requested and the response is not committed
    if (!create) {
        return null;
    }
    boolean trackModesIncludesCookie =
            context.getServletContext().getEffectiveSessionTrackingModes().contains(SessionTrackingMode.COOKIE);
    if (trackModesIncludesCookie && response.getResponse().isCommitted()) {
        throw new IllegalStateException(sm.getString("coyoteRequest.sessionCreateCommitted"));
    }

    // Re-use session IDs provided by the client in very limited
    // circumstances.
    String sessionId = getRequestedSessionId();
    if (requestedSessionSSL) {
        // If the session ID has been obtained from the SSL handshake then
        // use it.
    } else if (("/".equals(context.getSessionCookiePath())
            && isRequestedSessionIdFromCookie())) {
        /* This is the common(ish) use case: using the same session ID with
         * multiple web applications on the same host. Typically this is
         * used by Portlet implementations. It only works if sessions are
         * tracked via cookies. The cookie must have a path of "/" else it
         * won't be provided for requests to all web applications.
         *
         * Any session ID provided by the client should be for a session
         * that already exists somewhere on the host. Check if the context
         * is configured for this to be confirmed.
         */
        if (context.getValidateClientProvidedNewSessionId()) {
            boolean found = false;
            for (Container container : getHost().findChildren()) {
                Manager m = ((Context) container).getManager();
                if (m != null) {
                    try {
                        if (m.findSession(sessionId) != null) {
                            found = true;
                            break;
                        }
                    } catch (IOException e) {
                        // Ignore. Problems with this manager will be
                        // handled elsewhere.
                    }
                }
            }
            if (!found) {
                sessionId = null;
            }
        }
    } else {
        sessionId = null;
    }
    session = manager.createSession(sessionId);

    // Creating a new session cookie based on that session
    if (session != null && trackModesIncludesCookie) {
        Cookie cookie = ApplicationSessionCookieConfig.createSessionCookie(
                context, session.getIdInternal(), isSecure());

        response.addSessionCookieInternal(cookie);
    }

    if (session == null) {
        return null;
    }

    session.access();
    return session;
}
```



分析其内代码可知，整个获取Session的步骤如下：



1. 判断当前Request对象是否已经存在有效的Session信息，如果存在则返回此Session，否则进入下一步
2. 获取Session管理器，比如StandardManager
3. 从StandardManager的Session缓存中获取Session，如果有则返回此Session否则进入下一步
4. 创建Session
5. 创建保存Session ID的Cookie
6. 通过Session的access方法更新Session的访问时间以及访问次数



接下来浏览ManagerBase实现的createSession方法



>org.apache.catalina.session.ManagerBase.createSession()

```java
@Override
public Session createSession(String sessionId) {

    if ((maxActiveSessions >= 0) &&
            (getActiveSessions() >= maxActiveSessions)) {
        rejectedSessions++;
        throw new TooManyActiveSessionsException(
                sm.getString("managerBase.createSession.ise"),
                maxActiveSessions);
    }

    // Recycle or create a Session instance
    Session session = createEmptySession();

    // Initialize the properties of the new session and return it
    session.setNew(true);
    session.setValid(true);
    session.setCreationTime(System.currentTimeMillis());
    session.setMaxInactiveInterval(getContext().getSessionTimeout() * 60);
    String id = sessionId;
    if (id == null) {
        id = generateSessionId();
    }
    session.setId(id);
    sessionCounter++;

    SessionTiming timing = new SessionTiming(session.getCreationTime(), 0);
    synchronized (sessionCreationTiming) {
        sessionCreationTiming.add(timing);
        sessionCreationTiming.poll();
    }
    return session;
}
```



至此，Session的创建与分配就介绍到这



## Session追踪



HTTP是一种无状态的协议，如果一个客户端只是单纯的一个请求，服务端并不需要知道一连串的请求是否来自于相同的客户端，而且也不需要担心客户端是否处于连接状态。但是这样的通信协议使得服务器端难以判断所连接的客户端是否是同一个人。当进行Web程序开发时，必须想办法将相关的请求结合一起，并努力维持用户的状态在服务器上，这就引出了会话最终（session tracking）



Tomcat追踪Session主要借助其ID，因此在接收到请求后应该需要拿到此请求对应的会话ID，这样才能够和StandardManager的缓存中维护的Session相匹配，达到Session追踪的效果。在Tomcat请求原理中介绍了`CoyoteAdapter.service()`调用的`postParseRequest()`，其内有这么一段代码



> org.apache.catalina.connector.CoyoteAdapter.postParseRequest()节选

```java
String sessionID;
if (request.getServletContext().getEffectiveSessionTrackingModes()
        .contains(SessionTrackingMode.URL)) {

    // Get the session ID if there was one
    sessionID = request.getPathParameter(
            SessionConfig.getSessionUriParamName(
                    request.getContext()));
    if (sessionID != null) {
        request.setRequestedSessionId(sessionID);
        request.setRequestedSessionURL(true);
    }
}

// Look for session ID in cookies and SSL session
try {
    parseSessionCookiesId(request);
} catch (IllegalArgumentException e) {
    // Too many cookies
    if (!response.isError()) {
        response.setError();
        response.sendError(400);
    }
    return true;
}
parseSessionSslId(request);
```



其内执行的步骤如下：

1. 如果开启了会话跟踪（session tracking），则需要从缓存中获取维护的Session ID
2. 从请求所带的Cookie中获取Session ID
3. 如果Cookie没有携带Session ID，但是开启了会话跟踪（session tracking），则可以从SSL中获取SessionID



**从缓存中获取维护的Session ID**



`CoyoteAdapter.service()`调用的`postParseRequest()`中使用了`getSessionUriParamName()`获取Session的参数名称



> org.apache.catalina.util.SessionConfig.getSessionUriParamName()

```java
public static String getSessionUriParamName(Context context) {

    String result = getConfiguredSessionCookieName(context);

    if (result == null) {
        result = DEFAULT_SESSION_PARAMETER_NAME;
    }

    return result;
}
```



从中可以看出，`getSessionUriParamName()`首先调用`getConfiguredSessionCookieName()`获取Session的Cookie名称，如果没有则默认为jsessionid（常量DEFAULT_SESSION_PARAMETER)NAME的值），而getSessionUriParamName方法的返回值会作为`CoyoteAdapter.postParseRequest()`中调用的getPathParameter方法的参数查询Session ID



> org.apache.coyote.Request.getPathParameter()

```java
public String getPathParameter(String name) {
    return pathParameters.get(name);
}
```



### 从请求所带的Cookie中获取Session ID



`CoyoteAdapter.postParseRequest()`中调用了`parseSessionCookieId()`从Cookie中获取Session ID



> org.apache.catalina.connector.CoyoteAdapter.parseSessionCookiesId()

```java
protected void parseSessionCookiesId(Request request) {

    // If session tracking via cookies has been disabled for the current
    // context, don't go looking for a session ID in a cookie as a cookie
    // from a parent context with a session ID may be present which would
    // overwrite the valid session ID encoded in the URL
    Context context = request.getMappingData().context;
    if (context != null && !context.getServletContext()
            .getEffectiveSessionTrackingModes().contains(
                    SessionTrackingMode.COOKIE)) {
        return;
    }

    // Parse session id from cookies
    ServerCookies serverCookies = request.getServerCookies();
    int count = serverCookies.getCookieCount();
    if (count <= 0) {
        return;
    }

    String sessionCookieName = SessionConfig.getSessionCookieName(context);

    for (int i = 0; i < count; i++) {
        ServerCookie scookie = serverCookies.getCookie(i);
        if (scookie.getName().equals(sessionCookieName)) {
            // Override anything requested in the URL
            if (!request.isRequestedSessionIdFromCookie()) {
                // Accept only the first session id cookie
                convertMB(scookie.getValue());
                request.setRequestedSessionId
                    (scookie.getValue().toString());
                request.setRequestedSessionCookie(true);
                request.setRequestedSessionURL(false);
                if (log.isDebugEnabled()) {
                    log.debug(" Requested cookie session id is " +
                        request.getRequestedSessionId());
                }
            } else {
                if (!request.isRequestedSessionIdValid()) {
                    // Replace the session id until one is valid
                    convertMB(scookie.getValue());
                    request.setRequestedSessionId
                        (scookie.getValue().toString());
                }
            }
        }
    }

}
```



### 从SSL中获取Session ID



`CoyoteAdapter.postParseRequest()`中调用了`parseSessionSslId()`从SSL中获取Session ID



> org.apache.catalina.connector.CoyoteAdapter.parseSessionSslId()

```java
protected void parseSessionSslId(Request request) {
    if (request.getRequestedSessionId() == null &&
            SSL_ONLY.equals(request.getServletContext()
                    .getEffectiveSessionTrackingModes()) &&
                    request.connector.secure) {
        String sessionId = (String) request.getAttribute(SSLSupport.SESSION_ID_KEY);
        if (sessionId != null) {
            request.setRequestedSessionId(sessionId);
            request.setRequestedSessionSSL(true);
        }
    }
}
```



## Session销毁



在Tomcat生命周期中介绍了容器的生命周期管理相关的内容，StandardEngine作为容器，其启动过程中也会调用startInternal方法



> org.apache.catalina.core.StandardEngine.startInternal()

```java
@Override
protected synchronized void startInternal() throws LifecycleException {

    // Log our server identification information
    if (log.isInfoEnabled()) {
        log.info(sm.getString("standardEngine.start", ServerInfo.getServerInfo()));
    }

    // Standard container startup
    super.startInternal();
}
```



`StandardEngine.startInternal()`实际代理了父类`ContainerBase.startInternal()`



> org.apache.catalina.core.ContainerBase.startInternal()

```java
@Override
protected synchronized void startInternal() throws LifecycleException {

    // Start our subordinate components, if any
    logger = null;
    getLogger();
    Cluster cluster = getClusterInternal();
    if (cluster instanceof Lifecycle) {
        ((Lifecycle) cluster).start();
    }
    Realm realm = getRealmInternal();
    if (realm instanceof Lifecycle) {
        ((Lifecycle) realm).start();
    }

    // Start our child containers, if any
    Container children[] = findChildren();
    List<Future<Void>> results = new ArrayList<>();
    for (Container child : children) {
        results.add(startStopExecutor.submit(new StartChild(child)));
    }

    MultiThrowable multiThrowable = null;

    for (Future<Void> result : results) {
        try {
            result.get();
        } catch (Throwable e) {
            log.error(sm.getString("containerBase.threadedStartFailed"), e);
            if (multiThrowable == null) {
                multiThrowable = new MultiThrowable();
            }
            multiThrowable.add(e);
        }

    }
    if (multiThrowable != null) {
        throw new LifecycleException(sm.getString("containerBase.threadedStartFailed"),
                multiThrowable.getThrowable());
    }

    // Start the Valves in our pipeline (including the basic), if any
    if (pipeline instanceof Lifecycle) {
        ((Lifecycle) pipeline).start();
    }

    setState(LifecycleState.STARTING);

    // Start our thread
    if (backgroundProcessorDelay > 0) {
        monitorFuture = Container.getService(ContainerBase.this).getServer()
                .getUtilityExecutor().scheduleWithFixedDelay(
                        new ContainerBackgroundProcessorMonitor(), 0, 60, TimeUnit.SECONDS);
    }
}
```



其内一开始对各种子容器进行了启动，最后启动线程加载`ContainerBackgroundProcessorMonitor`类，而该类的run方法会调用threadStart方法



> org.apache.catalina.core.ContainerBase.ContainerBackgroundProcessorMonitor ()

```java
protected class ContainerBackgroundProcessorMonitor implements Runnable {
    @Override
    public void run() {
        if (getState().isAvailable()) {
            threadStart();
        }
    }
}
```



> org.apache.catalina.core.ContainerBase.threadStart()

```java
protected void threadStart() {
    if (backgroundProcessorDelay > 0
            && (getState().isAvailable() || LifecycleState.STARTING_PREP.equals(getState()))
            && (backgroundProcessorFuture == null || backgroundProcessorFuture.isDone())) {
        if (backgroundProcessorFuture != null && backgroundProcessorFuture.isDone()) {
            // There was an error executing the scheduled task, get it and log it
            try {
                backgroundProcessorFuture.get();
            } catch (InterruptedException | ExecutionException e) {
                log.error(sm.getString("containerBase.backgroundProcess.error"), e);
            }
        }
        backgroundProcessorFuture = Container.getService(this).getServer().getUtilityExecutor()
                .scheduleWithFixedDelay(new ContainerBackgroundProcessor(),
                        backgroundProcessorDelay, backgroundProcessorDelay,
                        TimeUnit.SECONDS);
    }
```



threadStart方法启动了一个后台线程，任务为加载`ContainerBackgroundProcessor`类，该类的run方法中调用了`processChildren()`



> org.apache.catalina.core.ContainerBase.ContainerBackgroundProcessor ()

```java
protected class ContainerBackgroundProcessor implements Runnable {

    @Override
    public void run() {
        processChildren(ContainerBase.this);
    }

    protected void processChildren(Container container) {
        ClassLoader originalClassLoader = null;

        try {
            if (container instanceof Context) {
                Loader loader = ((Context) container).getLoader();
                // Loader will be null for FailedContext instances
                if (loader == null) {
                    return;
                }

                // Ensure background processing for Contexts and Wrappers
                // is performed under the web app's class loader
                originalClassLoader = ((Context) container).bind(false, null);
            }
            container.backgroundProcess();
            Container[] children = container.findChildren();
            for (Container child : children) {
                if (child.getBackgroundProcessorDelay() <= 0) {
                    processChildren(child);
                }
            }
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            log.error(sm.getString("containerBase.backgroundProcess.error"), t);
        } finally {
            if (container instanceof Context) {
                ((Context) container).unbind(false, originalClassLoader);
            }
        }
    }
}
```



`processChildren()`会不断迭代StandardEngine的子容器并调用这些子容器的backgroundProcess方法，这里直接浏览StandardEngine的孙子容器StandardManager的backgroundProcess实现，即MangerBase的backgroundProcess方法



> org.apache.catalina.session.ManagerBase.backgroundProcess()

```java
@Override
public void backgroundProcess() {
    count = (count + 1) % processExpiresFrequency;
    if (count == 0)
        processExpires();
}
```



backgroundProcess里实现了一个简单的算法：

**count**：计数器，起始为0

**processExpiresFrequency**：执行processExpires方法的频率，默认为6



每执行一次backgroundProcess方法，count会增加1，每当count+1与processExpiresFrequency求模等于0，则调用processExpires。简而言之，每执行processExpiresFrequency指定次数的backgroundProcess方法，执行一次processExpires方法



> org.apache.catalina.session.ManagerBase.processExpires()

```java
public void processExpires() {

    long timeNow = System.currentTimeMillis();
    Session sessions[] = findSessions();
    int expireHere = 0 ;

    if(log.isDebugEnabled())
        log.debug("Start expire sessions " + getName() + " at " + timeNow + " sessioncount " + sessions.length);
    for (Session session : sessions) {
        if (session != null && !session.isValid()) {
            expireHere++;
        }
    }
    long timeEnd = System.currentTimeMillis();
    if(log.isDebugEnabled())
         log.debug("End expire sessions " + getName() + " processingTime " + (timeEnd - timeNow) + " expired sessions: " + expireHere);
    processingTime += ( timeEnd - timeNow );

}
```



processExpires方法的执行步骤如下：

1. 从缓存中取出所有的Session
2. 逐个校验每个Session是否过期，处理已经过期的Session



Session的标准实现是StandardSession，其isValid方法的主要功能是判断Session是否过期，对于过期的Session，将其expiring状态改为ture。



判断过期的公式为：（（当前时间 - Session的最后访问时间）/ 1000） >= 最大访问间隔



> org.apache.catalina.session.StandardSession.isValid()

```java
@Override
public boolean isValid() {

    if (!this.isValid) {
        return false;
    }

    if (this.expiring) {
        return true;
    }

    if (ACTIVITY_CHECK && accessCount.get() > 0) {
        return true;
    }

    if (maxInactiveInterval > 0) {
        int timeIdle = (int) (getIdleTimeInternal() / 1000L);
        if (timeIdle >= maxInactiveInterval) {
            expire(true);
        }
    }

    return this.isValid;
}
```





## 总结

**Tomcat对于Session的管理过程包括创建、分配、维护、跟踪和销毁**









[SessionManager]:data:image/png;base64,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
[SessionInterface]:data:image/png;base64,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

