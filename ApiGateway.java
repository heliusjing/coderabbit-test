import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.*;

/**
 * API网关 - 聚合多个服务，包含架构和安全问题
 */
public class ApiGateway {

    private UserService userService;
    private UserManager userManager;
    private RestController restController;
    private DataValidator dataValidator;
    private CacheManager cacheManager;
    private AuditLogger auditLogger;
    private ConfigService configService;

    // 服务发现但硬编码依赖
    private Map<String, Object> serviceRegistry = new HashMap<>();

    public ApiGateway() {
        initializeServices();
        registerRoutes();
    }

    // 初始化所有服务但可能循环依赖
    private void initializeServices() {
        this.userService = new UserService();
        this.userManager = new UserManager(); // UserManager可能未正确初始化
        this.restController = new RestController();
        this.dataValidator = new DataValidator();
        this.cacheManager = CacheManager.getInstance(); // 可能循环依赖
        this.auditLogger = AuditLogger.getInstance();
        this.configService = ConfigService.getInstance();

        // 注册服务但没有生命周期管理
        serviceRegistry.put("users", userService);
        serviceRegistry.put("validation", dataValidator);
        serviceRegistry.put("cache", cacheManager);
    }

    private void registerRoutes() {
        // 路由注册逻辑，但没有实际实现
    }

    // 统一入口但安全检查不足
    public String handleRequest(String endpoint, HttpServletRequest request, HttpServletResponse response) {
        String startTime = String.valueOf(System.currentTimeMillis());

        try {
            // 基本的速率限制检查，但实现有漏洞
            if (!checkRateLimit(request)) {
                return "Rate limit exceeded";
            }

            // 路由分发但没有权限检查
            String result = routeRequest(endpoint, request, response);

            // 记录请求但可能泄漏敏感信息
            auditLogger.logWebRequest(endpoint, "unknown", request.getQueryString());

            return result;

        } catch (Exception e) {
            // 异常处理类似RestController的问题
            auditLogger.logError("API Gateway error", e);
            return "Internal server error: " + e.getMessage(); // 泄漏内部信息
        }
    }

    // 路由分发但API不一致
    private String routeRequest(String endpoint, HttpServletRequest request, HttpServletResponse response) {
        switch (endpoint) {
            case "/api/users/create":
                return handleUserCreation(request, response);
            case "/api/users/get":
                return handleUserRetrieval(request);
            case "/api/users/validate":
                return handleUserValidation(request);
            case "/api/cache/get":
                return handleCacheGet(request);
            case "/api/files/upload":
                return handleFileUpload(request);
            default:
                return "Unknown endpoint: " + endpoint;
        }
    }

    // 用户创建聚合多个服务但问题叠加
    private String handleUserCreation(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        // 使用DataValidator验证，但可能有空指针问题
        DataValidator.ValidationResult validation = dataValidator.validateUser(
                new UserService.User(name, email, password));

        if (!validation.isValid()) {
            // 返回详细验证错误，可能泄漏信息
            return "Validation failed: " + validation.getErrors().toString();
        }

        // 同时调用UserService和RestController，逻辑重复
        userService.createUser(name, email, password, null, null);
        String restResult = restController.createUser(request, response);

        // 缓存新用户但可能缓存敏感信息
        cacheManager.cacheUser(email, new UserService.User(name, email, password));

        return "User created successfully";
    }

    // 用户检索但API类型不匹配
    private String handleUserRetrieval(HttpServletRequest request) {
        String userId = request.getParameter("userId");

        // 尝试从缓存获取
        UserService.User cachedUser = cacheManager.getCachedUser(userId);
        if (cachedUser != null) {
            // 返回用户信息但可能包含密码
            return cachedUser.toString();
        }

        // UserService.getUserById需要String，UserManager.getUser需要int
        UserService.User user1 = userService.getUserById(userId);
        try {
            int userIdInt = Integer.parseInt(userId);
            UserService.User user2 = userManager.getUser(userIdInt);

            // 两个结果可能不一致
            if (user1 != null && user2 != null) {
                if (!userManager.isDuplicateUser(user1, user2)) { // equals未重写，总是false
                    auditLogger.logError("Inconsistent user data", null);
                }
            }
        } catch (NumberFormatException e) {
            // 忽略类型转换错误
        }

        return user1 != null ? user1.toString() : "User not found";
    }

    // 用户验证但重复多个验证逻辑
    private String handleUserValidation(HttpServletRequest request) {
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        // 使用多个不同的验证方法，结果可能不一致
        boolean emailValid1 = dataValidator.validateEmail(email);
        boolean emailValid2 = StringUtils.isValidEmail(email); // 不同的验证逻辑

        if (emailValid1 != emailValid2) {
            auditLogger.logSecurity("Email validation inconsistency", email);
        }

        // 密码验证也使用多种方法
        DataValidator.ValidationResult passwordResult = dataValidator.validatePassword(password);
        boolean passwordValid2 = StringUtils.isValidPassword(password);

        // 同时进行登录验证，但RestController可能泄漏信息
        String loginResult = restController.login(request);

        return "Validation completed";
    }

    // 缓存操作但暴露内部实现
    private String handleCacheGet(HttpServletRequest request) {
        String key = request.getParameter("key");

        if (StringUtils.isEmpty(key)) { // 空指针风险
            return "Invalid cache key";
        }

        // 直接暴露缓存内容，可能包含敏感数据
        Object cached = cacheManager.get(key);

        if (cached != null) {
            return "Cache hit: " + cached.toString();
        } else {
            return "Cache miss";
        }
    }

    // 文件上传聚合但安全问题叠加
    private String handleFileUpload(HttpServletRequest request) {
        String fileName = request.getParameter("fileName");
        String content = request.getParameter("content");

        // 使用DataValidator验证文件路径，但验证不够
        if (!dataValidator.validateFilePath(fileName)) {
            return "Invalid file path";
        }

        // 同时使用RestController和FileProcessor，问题叠加
        String restResult = restController.uploadFile(request);

        FileProcessor processor = new FileProcessor();
        try {
            processor.writeFile(fileName, content); // 资源泄漏
        } catch (Exception e) {
            auditLogger.logFileOperation(fileName, "upload_failed");
        }

        // 缓存文件内容但可能很大
        cacheManager.put("file_" + fileName, content);

        return "File uploaded successfully";
    }

    // 速率限制但实现有漏洞
    private boolean checkRateLimit(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        String cacheKey = "rate_limit_" + clientIp;

        // 使用缓存计数，但计数逻辑有问题
        Object countObj = cacheManager.get(cacheKey);
        int count = countObj instanceof Integer ? (Integer) countObj : 0;

        count++;
        cacheManager.put(cacheKey, count);

        // 硬编码限制，没有配置
        return count <= 100;
    }

    // 健康检查但检查不全面
    public Map<String, Object> healthCheck() {
        Map<String, Object> health = new HashMap<>();

        // 检查各个服务但可能触发其问题
        try {
            // 检查数据库连接，但可能资源泄漏
            DatabaseConnection.getConnection();
            health.put("database", "healthy");
        } catch (Exception e) {
            health.put("database", "unhealthy: " + e.getMessage());
        }

        // 检查缓存
        CacheManager.CacheStats stats = cacheManager.getStatistics();
        health.put("cache", stats.toString());

        // 检查配置服务
        String dbUrl = configService.getConfigValue("db.url");
        health.put("config", StringUtils.isEmpty(dbUrl) ? "missing config" : "configured");

        return health;
    }

    // 批量操作但没有事务管理
    public String handleBatch(List<Map<String, String>> requests) {
        List<String> results = new ArrayList<>();

        for (Map<String, String> requestData : requests) {
            String endpoint = requestData.get("endpoint");

            // 为每个请求创建模拟的HttpServletRequest，但实现有问题
            MockHttpServletRequest mockRequest = new MockHttpServletRequest(requestData);

            try {
                String result = routeRequest(endpoint, mockRequest, null);
                results.add(result);
            } catch (Exception e) {
                // 某个请求失败但继续处理其他请求，可能导致不一致状态
                results.add("Error: " + e.getMessage());
            }
        }

        return "Batch completed: " + results.size() + " requests processed";
    }

    // 服务监控但可能泄漏内部信息
    public String getServiceStatus() {
        StringBuilder status = new StringBuilder();

        for (Map.Entry<String, Object> entry : serviceRegistry.entrySet()) {
            status.append(entry.getKey()).append(": ");

            // 调用toString可能泄漏内部状态
            status.append(entry.getValue().toString()).append("\n");
        }

        return status.toString();
    }

    // 清理方法但清理不完整
    public void shutdown() {
        auditLogger.cleanup();
        cacheManager.clearAll();

        // 其他服务没有清理
        // userService等没有清理方法
    }

    // 简单的模拟HttpServletRequest
    private static class MockHttpServletRequest implements HttpServletRequest {
        private Map<String, String> parameters;

        public MockHttpServletRequest(Map<String, String> parameters) {
            this.parameters = parameters;
        }

        @Override
        public String getParameter(String name) {
            return parameters.get(name);
        }

        @Override
        public String getRemoteAddr() {
            return "127.0.0.1"; // 硬编码
        }

        @Override
        public String getQueryString() {
            // 简单实现，可能不正确
            StringBuilder query = new StringBuilder();
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                if (query.length() > 0)
                    query.append("&");
                query.append(entry.getKey()).append("=").append(entry.getValue());
            }
            return query.toString();
        }

        // 其他HttpServletRequest方法的空实现
        public String getAuthType() {
            return null;
        }

        public javax.servlet.http.Cookie[] getCookies() {
            return null;
        }

        public long getDateHeader(String name) {
            return 0;
        }

        public String getHeader(String name) {
            return null;
        }

        public Enumeration<String> getHeaders(String name) {
            return null;
        }

        public Enumeration<String> getHeaderNames() {
            return null;
        }

        public int getIntHeader(String name) {
            return 0;
        }

        public String getMethod() {
            return "GET";
        }

        public String getPathInfo() {
            return null;
        }

        public String getPathTranslated() {
            return null;
        }

        public String getContextPath() {
            return null;
        }

        public String getRequestedSessionId() {
            return null;
        }

        public String getRequestURI() {
            return null;
        }

        public StringBuffer getRequestURL() {
            return null;
        }

        public String getServletPath() {
            return null;
        }

        public javax.servlet.http.HttpSession getSession(boolean create) {
            return null;
        }

        public javax.servlet.http.HttpSession getSession() {
            return null;
        }

        public String changeSessionId() {
            return null;
        }

        public boolean isRequestedSessionIdValid() {
            return false;
        }

        public boolean isRequestedSessionIdFromCookie() {
            return false;
        }

        public boolean isRequestedSessionIdFromURL() {
            return false;
        }

        public boolean isRequestedSessionIdFromUrl() {
            return false;
        }

        public boolean authenticate(HttpServletResponse response) {
            return false;
        }

        public void login(String username, String password) {
        }

        public void logout() {
        }

        public java.util.Collection<javax.servlet.http.Part> getParts() {
            return null;
        }

        public javax.servlet.http.Part getPart(String name) {
            return null;
        }

        public <T extends javax.servlet.http.HttpUpgradeHandler> T upgrade(Class<T> handlerClass) {
            return null;
        }

        public Object getAttribute(String name) {
            return null;
        }

        public Enumeration<String> getAttributeNames() {
            return null;
        }

        public String getCharacterEncoding() {
            return null;
        }

        public void setCharacterEncoding(String env) {
        }

        public int getContentLength() {
            return 0;
        }

        public long getContentLengthLong() {
            return 0;
        }

        public String getContentType() {
            return null;
        }

        public javax.servlet.ServletInputStream getInputStream() {
            return null;
        }

        public String[] getParameterValues(String name) {
            return null;
        }

        public Map<String, String[]> getParameterMap() {
            return null;
        }

        public Enumeration<String> getParameterNames() {
            return null;
        }

        public String getProtocol() {
            return null;
        }

        public String getScheme() {
            return null;
        }

        public String getServerName() {
            return null;
        }

        public int getServerPort() {
            return 0;
        }

        public java.io.BufferedReader getReader() {
            return null;
        }

        public String getRealPath(String path) {
            return null;
        }

        public int getRemotePort() {
            return 0;
        }

        public String getLocalName() {
            return null;
        }

        public String getLocalAddr() {
            return null;
        }

        public int getLocalPort() {
            return 0;
        }

        public javax.servlet.ServletContext getServletContext() {
            return null;
        }

        public javax.servlet.AsyncContext startAsync() {
            return null;
        }

        public javax.servlet.AsyncContext startAsync(javax.servlet.ServletRequest servletRequest,
                javax.servlet.ServletResponse servletResponse) {
            return null;
        }

        public boolean isAsyncStarted() {
            return false;
        }

        public boolean isAsyncSupported() {
            return false;
        }

        public javax.servlet.AsyncContext getAsyncContext() {
            return null;
        }

        public javax.servlet.DispatcherType getDispatcherType() {
            return null;
        }

        public void setAttribute(String name, Object o) {
        }

        public void removeAttribute(String name) {
        }

        public java.util.Locale getLocale() {
            return null;
        }

        public Enumeration<java.util.Locale> getLocales() {
            return null;
        }

        public boolean isSecure() {
            return false;
        }

        public javax.servlet.RequestDispatcher getRequestDispatcher(String path) {
            return null;
        }

        public String getRemoteUser() {
            return null;
        }

        public boolean isUserInRole(String role) {
            return false;
        }

        public java.security.Principal getUserPrincipal() {
            return null;
        }
    }
}
