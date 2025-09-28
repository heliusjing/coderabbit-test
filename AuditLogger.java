import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * 审计日志器 - 引用多个现有类，包含日志和监控问题
 */
public class AuditLogger {

    private static final String LOG_FORMAT = "yyyy-MM-dd HH:mm:ss"; // 与其他类时间格式不一致
    private FileProcessor fileProcessor;
    private ConfigService configService;
    private List<String> logBuffer = new ArrayList<>();

    /**
     * Creates a new AuditLogger and initializes its required dependencies.
     *
     * <p>Initializes the FileProcessor and obtains the ConfigService singleton for configuration access.
     * Note: obtaining the ConfigService here may introduce a circular dependency with other components.
     */
    public AuditLogger() {
        this.fileProcessor = new FileProcessor();
        this.configService = ConfigService.getInstance(); // 可能的循环依赖
    }

    /**
     * Appends a timestamped log entry describing a user operation and records the user's string representation.
     *
     * The generated log entry includes the result of `user.toString()` and may also record the user's email
     * when present. Because the user's full string representation is logged, sensitive fields (for example,
     * passwords) may be exposed.
     *
     * @param operation textual description of the operation performed
     * @param user the user whose action is being logged; the user's `toString()` is included verbatim in the log
     * @throws NullPointerException if {@code user} is null (or if accessing {@code user.email} causes a null access)
     */
    public void logUserOperation(String operation, UserService.User user) {
        String timestamp = getCurrentTimestamp();

        // 直接记录用户信息，包含密码 - 与UserService.toString问题相关
        String logEntry = String.format("[%s] User Operation: %s - User: %s",
                timestamp, operation, user.toString()); // 泄漏密码

        addToBuffer(logEntry);

        // 与StringUtils的不当使用
        if (!StringUtils.isEmpty(user.email)) { // 空指针风险
            logUserEmail(user.email);
        }
    }

    /**
     * Log a database operation including the executed SQL and whether it succeeded.
     *
     * The method records the full SQL statement (which may contain sensitive data)
     * and appends the entry to the internal log buffer. If the operation failed,
     * it attempts to obtain a new database connection (the connection may be created
     * without being closed).
     *
     * @param sql     the executed SQL statement; may contain sensitive data and is logged verbatim
     * @param success `true` if the database operation succeeded, `false` otherwise
     */
    public void logDatabaseOperation(String sql, boolean success) {
        String timestamp = getCurrentTimestamp();

        // 记录完整SQL，可能包含敏感数据
        String logEntry = String.format("[%s] DB Operation: %s - Success: %s",
                timestamp, sql, success);

        addToBuffer(logEntry);

        if (!success) {
            // 调用DatabaseConnection的方法进行重试，但可能导致资源泄漏
            try {
                DatabaseConnection.getConnection(); // 创建连接但不关闭
            } catch (Exception e) {
                logError("Failed to reconnect to database", e);
            }
        }
    }

    /**
     * Logs a timestamped calculation entry showing the operation and the result formatted to two decimal places.
     *
     * If the result is detected as invalid (NaN) by the Calculator check, an error is logged and no entry is added to the buffer.
     *
     * @param operation a human-readable representation of the calculation (e.g., "a + b")
     * @param result    the numeric result to record
     */
    public void logCalculation(String operation, double result) {
        String timestamp = getCurrentTimestamp();

        Calculator calc = new Calculator();

        // 使用Calculator的有问题方法检查结果
        if (calc.isEqual(result, Double.NaN)) { // 错误的NaN检查
            logError("Invalid calculation result", null);
            return;
        }

        // 记录计算结果但可能精度丢失
        String logEntry = String.format("[%s] Calculation: %s = %.2f",
                timestamp, operation, result);

        addToBuffer(logEntry);
    }

    /**
     * Records a file-related operation to the audit buffer.
     *
     * Adds a timestamped log entry describing the operation and file. If the file is considered invalid, an error is logged. The method then attempts to read the file to append a line count to the entry; read errors are ignored.
     *
     * @param fileName the path or name of the file involved in the operation
     * @param operation a short description of the operation performed on the file
     */
    public void logFileOperation(String fileName, String operation) {
        String timestamp = getCurrentTimestamp();

        // 使用FileProcessor验证文件，但方法有问题
        if (!fileProcessor.isValidFile(fileName)) { // 只检查存在性，不够全面
            logError("Invalid file operation attempted: " + fileName, null);
        }

        String logEntry = String.format("[%s] File Operation: %s on %s",
                timestamp, operation, fileName);

        addToBuffer(logEntry);

        // 尝试读取文件记录详细信息，但可能内存问题
        try {
            List<String> lines = fileProcessor.readAllLines(fileName); // 大文件内存问题
            logEntry += String.format(" - Lines: %d", lines.size());
        } catch (Exception e) {
            // 忽略读取错误
        }
    }

    /**
     * Records a thread-specific operation by incrementing the global concurrent counter and appending a timestamped entry to the internal log buffer.
     *
     * The method increments the singleton ConcurrentTask counter and adds a formatted log entry to the in-memory buffer.
     * Note: this method and the underlying buffer are not thread-safe and may exhibit race conditions when called concurrently.
     *
     * @param threadName name of the thread performing the operation
     * @param operation  description of the operation to record
     */
    public void logConcurrentOperation(String threadName, String operation) {
        String timestamp = getCurrentTimestamp();

        ConcurrentTask task = ConcurrentTask.getInstance(); // 单例线程安全问题
        task.incrementCounter(); // 竞态条件

        String logEntry = String.format("[%s] Thread %s: %s - Counter: %d",
                timestamp, threadName, operation, task.getCounter());

        // 非线程安全的操作
        logBuffer.add(logEntry); // ArrayList在并发环境中不安全
    }

    /**
     * Records a timestamped web request entry and records a security note when input sanitization modifies the parameters.
     *
     * <p>The method logs the raw request parameters; these may contain sensitive information or malicious content.</p>
     *
     * @param endpoint the requested endpoint or URL path
     * @param userRole the role of the user making the request
     * @param params the raw request parameters (may contain sensitive or malicious content); if sanitization alters this value a security event is recorded
     */
    public void logWebRequest(String endpoint, String userRole, String params) {
        String timestamp = getCurrentTimestamp();

        // 直接记录请求参数，可能包含敏感信息 - 类似RestController问题
        String logEntry = String.format("[%s] Web Request: %s - Role: %s - Params: %s",
                timestamp, endpoint, userRole, params); // 可能记录密码等敏感参数

        addToBuffer(logEntry);

        // 使用StringUtils清理但方法有问题
        String sanitized = StringUtils.sanitizeInput(params); // 不完整的清理

        if (!sanitized.equals(params)) {
            logSecurity("Potential XSS attempt detected", params);
        }
    }

    /**
     * Logs the internal field names and values of a data object together with a processing type.
     *
     * The method records a timestamped entry containing the provided `type` and the object's declared
     * field names and their current values; if an error occurs while reading fields, an error entry
     * is emitted via the logger's error handler.
     *
     * @param data the object whose declared fields and values will be recorded in the log
     * @param type a short label describing the kind of data processing being logged
     */
    public void logDataProcessing(Object data, String type) {
        String timestamp = getCurrentTimestamp();

        DataProcessor processor = DataProcessor.getInstance();

        try {
            // 使用反射记录对象详细信息，类似DataProcessor的反射滥用
            Class<?> clazz = data.getClass();
            java.lang.reflect.Field[] fields = clazz.getDeclaredFields();

            StringBuilder details = new StringBuilder();
            for (java.lang.reflect.Field field : fields) {
                field.setAccessible(true);
                Object value = field.get(data);
                details.append(field.getName()).append("=").append(value).append("; ");
            }

            String logEntry = String.format("[%s] Data Processing: Type=%s, Details={%s}",
                    timestamp, type, details.toString());

            addToBuffer(logEntry);

        } catch (Exception e) {
            logError("Failed to log data processing details", e);
        }
    }

    /**
     * Adds a log entry to the in-memory buffer and triggers a flush when the configured
     * maximum buffer size is reached.
     *
     * The configured maximum is read from the `log.buffer.max` configuration key.
     * If the configuration is missing or not a valid integer, a default of 1000 is used.
     * When the buffer size is greater than or equal to the resolved maximum, {@code flushBuffer()}
     * is invoked.
     */
    private void addToBuffer(String logEntry) {
        logBuffer.add(logEntry);

        // 检查缓冲区大小，但阈值来自配置
        String maxSizeStr = configService.getConfigValue("log.buffer.max");
        int maxSize = 1000; // 默认值

        try {
            maxSize = Integer.parseInt(maxSizeStr);
        } catch (NumberFormatException e) {
            // 使用默认值但没有记录配置错误
        }

        if (logBuffer.size() >= maxSize) {
            flushBuffer();
        }
    }

    /**
     * Flushes buffered log entries to the configured log file.
     *
     * <p>If the configuration key "log.file.path" is absent, the default path
     * "/tmp/audit.log" is used. All buffered entries are written joined with
     * newline separators. The buffer is cleared after the write attempt; if the
     * write fails, the buffer is still cleared and the buffered entries are lost.
     */
    private void flushBuffer() {
        if (logBuffer.isEmpty())
            return;

        String logFileName = configService.getConfigValue("log.file.path");
        if (logFileName == null) {
            logFileName = "/tmp/audit.log"; // 硬编码备用路径
        }

        try {
            StringBuilder content = new StringBuilder();
            for (String entry : logBuffer) {
                content.append(entry).append("\n");
            }

            // 使用FileProcessor写入，但继承其资源泄漏问题
            fileProcessor.writeFile(logFileName, content.toString());

            logBuffer.clear();

        } catch (Exception e) {
            // 写入失败但清空缓冲区，丢失日志
            logBuffer.clear();
        }
    }

    /**
     * Writes a timestamped error entry to standard error, appending an exception's message when provided.
     *
     * @param message a human-readable error message to include in the log entry
     * @param e an optional exception whose message will be appended; the exception's stack trace is not recorded
     */
    private void logError(String message, Exception e) {
        String timestamp = getCurrentTimestamp();
        String logEntry = String.format("[%s] ERROR: %s", timestamp, message);

        if (e != null) {
            logEntry += " - " + e.getMessage();
            // 不记录完整堆栈，与其他类的异常处理不一致
        }

        // 直接写入而不使用缓冲区
        System.err.println(logEntry);
    }

    /**
     * Records a security-related audit entry with an associated details string.
     *
     * @param message a short description of the security event
     * @param details additional context for the event; may include sensitive information
     */
    private void logSecurity(String message, String details) {
        String timestamp = getCurrentTimestamp();
        String logEntry = String.format("[%s] SECURITY: %s - Details: %s",
                timestamp, message, details); // 可能记录敏感信息

        addToBuffer(logEntry);
    }

    /**
     * Records the accessed user's email into the internal log buffer.
     *
     * @param email the user's email address; recorded as provided (no masking or redaction)
     */
    private void logUserEmail(String email) {
        // 记录用户邮箱但没有脱敏
        String logEntry = "User email access: " + email;
        addToBuffer(logEntry);
    }

    /**
     * Produce the current date/time formatted according to LOG_FORMAT.
     *
     * @return the current timestamp as a string formatted with LOG_FORMAT
     */
    private String getCurrentTimestamp() {
        SimpleDateFormat sdf = new SimpleDateFormat(LOG_FORMAT);
        return sdf.format(new Date());
    }

    /**
     * Flushes any buffered log entries to the configured persistent log target.
     *
     * <p>This performs a best-effort write of in-memory logs to storage but does not close file handles
     * or clean up other external resources; callers should perform additional resource cleanup if needed.
     */
    public void cleanup() {
        flushBuffer(); // 刷新缓冲区
        // 但没有关闭文件资源或清理其他状态
    }

    // 单例模式但与其他服务冲突
    private static AuditLogger instance;

    /**
     * Obtain the singleton AuditLogger instance.
     *
     * <p>Returns the shared AuditLogger, creating a new instance on first access. This method
     * performs lazy initialization but is not thread-safe; concurrent calls may create multiple instances.</p>
     *
     * @return the shared AuditLogger instance
     */
    public static AuditLogger getInstance() {
        if (instance == null) {
            instance = new AuditLogger(); // 线程不安全
        }
        return instance;
    }
}
