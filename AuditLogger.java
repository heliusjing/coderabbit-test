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
     * Creates a new AuditLogger, instantiating its FileProcessor and obtaining the ConfigService singleton.
     *
     * <p>The constructor creates a FileProcessor instance for file I/O and calls {@code ConfigService.getInstance()}
     * to acquire configuration. This may introduce a circular dependency if ConfigService depends on AuditLogger.</p>
     */
    public AuditLogger() {
        this.fileProcessor = new FileProcessor();
        this.configService = ConfigService.getInstance(); // 可能的循环依赖
    }

    /**
     * Records a user operation by appending a log entry that includes the provided operation
     * and the result of calling `user.toString()`. If `user.email` is not empty, also records
     * the email via {@code logUserEmail}.
     *
     * Note: the method writes the verbatim `user.toString()` output into the log and therefore
     * may include sensitive user fields if `toString()` exposes them.
     *
     * @param operation a short description of the user operation
     * @param user the user whose `toString()` representation will be recorded (included verbatim in the log; may contain sensitive fields)
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
     * Record a database operation including the executed SQL and its success status into the audit buffer.
     *
     * The full SQL is recorded verbatim (it may contain sensitive data). If `success` is false, a
     * reconnection attempt is made and any reconnection failure is logged via the error logger.
     *
     * @param sql     the executed SQL statement; recorded as-is and may contain sensitive information
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
     * Logs a calculation entry with the given operation and numeric result.
     *
     * If the result is NaN, an error entry is emitted and no calculation entry is buffered.
     * The buffered log entry formats the numeric result to two decimal places.
     *
     * @param operation a human-readable representation of the calculation (e.g., "a + b")
     * @param result    the numeric result of the calculation
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
     * Records a file-related audit entry for the given file and operation.
     *
     * Builds a timestamped log entry describing the operation on the specified file and adds it to the internal buffer.
     * If the file is considered invalid by the configured FileProcessor, an error is emitted via the logger.
     * The method also attempts to read the file to append a line count to the entry; read failures are ignored.
     *
     * @param fileName the path or identifier of the file being operated on
     * @param operation a short description of the file operation performed (e.g., "read", "write", "delete")
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
     * Records a concurrent operation by timestamping it, incrementing a shared counter, and appending a formatted entry to the internal log buffer.
     *
     * @param threadName the name or identifier of the thread performing the operation
     * @param operation a brief description of the operation performed
     * @implNote This method increments a shared ConcurrentTask counter and adds the entry to an in-memory buffer; both actions may exhibit race conditions in concurrent environments. 
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
     * Logs a web request entry containing the endpoint, user role, and raw request parameters, and flags potentially malicious input when sanitization changes the parameters.
     *
     * Records the raw `params` value in the audit buffer (may include sensitive data). If a sanitization step modifies `params`, a security event is recorded.
     *
     * @param endpoint the requested endpoint or path
     * @param userRole the role of the user making the request
     * @param params   the raw request parameters or payload
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
     * Logs the declared field names and values of a data object together with a processing type into the audit buffer.
     *
     * <p>The method inspects the object's declared fields (including non-public), captures each field as `name=value`
     * pairs, and appends a single formatted entry to the internal log buffer. If an error occurs while collecting
     * field values, an error entry is recorded via {@code logError} instead of adding a buffer entry.</p>
     *
     * @param data the object whose declared fields will be recorded; its field names and runtime values are captured
     * @param type a brief label describing the kind or category of data processing being logged
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
     * Adds a log entry to the internal buffer and flushes the buffer when the configured size threshold is reached.
     *
     * Reads the max buffer size from configuration key "log.buffer.max" and uses 1000 if the value is missing or not a valid integer.
     *
     * @param logEntry the log entry text to append to the buffer
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
     * Writes all buffered log entries to the configured log file (or "/tmp/audit.log" if none configured)
     * and clears the in-memory buffer.
     *
     * <p>If writing fails for any reason, the buffer is still cleared, causing buffered log entries to be lost.</p>
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
     * Logs an error entry to standard error including a timestamp and optional exception message.
     *
     * When an exception is provided, only the exception's message is appended (no stack trace).
     * The entry is written directly to System.err and is not added to the internal buffer.
     *
     * @param message human-readable error message to include in the log entry
     * @param e optional exception whose message will be appended if non-null
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
     * Record a security-related audit entry into the internal buffer.
     *
     * The entry is timestamped and includes the provided message and details, which are appended verbatim
     * (details may contain sensitive information).
     *
     * @param message short description of the security event
     * @param details additional context or data for the event; may include sensitive content
     */
    private void logSecurity(String message, String details) {
        String timestamp = getCurrentTimestamp();
        String logEntry = String.format("[%s] SECURITY: %s - Details: %s",
                timestamp, message, details); // 可能记录敏感信息

        addToBuffer(logEntry);
    }

    /**
     * Logs a user's email address to the audit buffer without masking or redaction.
     *
     * @param email the user's email address to record (stored verbatim)
     */
    private void logUserEmail(String email) {
        // 记录用户邮箱但没有脱敏
        String logEntry = "User email access: " + email;
        addToBuffer(logEntry);
    }

    /**
     * Formats the current date and time using the class's LOG_FORMAT.
     *
     * @return the current timestamp as a string formatted according to LOG_FORMAT
     */
    private String getCurrentTimestamp() {
        SimpleDateFormat sdf = new SimpleDateFormat(LOG_FORMAT);
        return sdf.format(new Date());
    }

    /**
     * Flushes any buffered log entries to persistent storage.
     *
     * <p>Writes all pending log entries from the in-memory buffer to the configured log file.
     * This method does not close file handles or release other external resources or internal
     * state; callers should perform additional cleanup if required.
     */
    public void cleanup() {
        flushBuffer(); // 刷新缓冲区
        // 但没有关闭文件资源或清理其他状态
    }

    // 单例模式但与其他服务冲突
    private static AuditLogger instance;

    /**
     * Get the shared AuditLogger singleton instance, creating it lazily if necessary.
     *
     * <p>Note: this lazy initialization is not thread-safe; concurrent callers may create multiple instances.</p>
     *
     * @return the singleton AuditLogger instance
     */
    public static AuditLogger getInstance() {
        if (instance == null) {
            instance = new AuditLogger(); // 线程不安全
        }
        return instance;
    }
}
