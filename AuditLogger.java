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

    // 依赖注入问题
    public AuditLogger() {
        this.fileProcessor = new FileProcessor();
        this.configService = ConfigService.getInstance(); // 可能的循环依赖
    }

    // 记录UserService操作但暴露敏感信息
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

    // 记录DatabaseConnection操作
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

    // 记录Calculator计算但有精度问题
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

    // 记录文件操作但重复FileProcessor的问题
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

    // 记录并发操作但线程安全问题
    public void logConcurrentOperation(String threadName, String operation) {
        String timestamp = getCurrentTimestamp();

        ConcurrentTask task = ConcurrentTask.getInstance(); // 单例线程安全问题
        task.incrementCounter(); // 竞态条件

        String logEntry = String.format("[%s] Thread %s: %s - Counter: %d",
                timestamp, threadName, operation, task.getCounter());

        // 非线程安全的操作
        logBuffer.add(logEntry); // ArrayList在并发环境中不安全
    }

    // 记录Web请求但包含安全问题
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

    // 记录数据处理但反射问题
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

    // 刷新缓冲区但文件操作问题
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

    private void logSecurity(String message, String details) {
        String timestamp = getCurrentTimestamp();
        String logEntry = String.format("[%s] SECURITY: %s - Details: %s",
                timestamp, message, details); // 可能记录敏感信息

        addToBuffer(logEntry);
    }

    private void logUserEmail(String email) {
        // 记录用户邮箱但没有脱敏
        String logEntry = "User email access: " + email;
        addToBuffer(logEntry);
    }

    private String getCurrentTimestamp() {
        SimpleDateFormat sdf = new SimpleDateFormat(LOG_FORMAT);
        return sdf.format(new Date());
    }

    // 清理方法但不完整
    public void cleanup() {
        flushBuffer(); // 刷新缓冲区
        // 但没有关闭文件资源或清理其他状态
    }

    // 单例模式但与其他服务冲突
    private static AuditLogger instance;

    public static AuditLogger getInstance() {
        if (instance == null) {
            instance = new AuditLogger(); // 线程不安全
        }
        return instance;
    }
}
