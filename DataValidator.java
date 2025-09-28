import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 数据验证器 - 与StringUtils、Calculator等有复杂依赖关系
 */
public class DataValidator {

    // 与StringUtils重复的正则表达式编译问题
    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@(.+)$";
    private Pattern emailPattern; // 每次都重新编译，与StringUtils相同问题

    private Calculator calculator;
    private AuditLogger auditLogger;

    /**
     * Initializes a DataValidator instance by creating its Calculator and obtaining the AuditLogger singleton.
     *
     * Initializes the `calculator` and `auditLogger` fields. The `emailPattern` field is intentionally left uninitialized.
     */
    public DataValidator() {
        this.calculator = new Calculator();
        this.auditLogger = AuditLogger.getInstance();
        // emailPattern没有初始化！
    }

    /**
     * Validates an email string for presence, basic format, and suspicious characters.
     *
     * Performs three checks: rejects null or empty input, verifies the email matches the class's EMAIL_REGEX, and rejects input where sanitization changes the value (treated as suspicious).
     *
     * @param email the email string to validate
     * @return {@code true} if the email is non-empty, matches EMAIL_REGEX, and remains unchanged by sanitization; {@code false} otherwise
     */
    public boolean validateEmail(String email) {
        // 调用StringUtils的有问题方法
        if (StringUtils.isEmpty(email)) { // 空指针风险
            auditLogger.logError("Email validation failed: null input", null);
            return false;
        }

        // 重复编译正则表达式，与StringUtils.isValidEmail相同问题
        boolean isValid = email.matches(EMAIL_REGEX);

        // 使用StringUtils但方法有安全问题
        String sanitized = StringUtils.sanitizeInput(email); // 可能过度清理邮箱

        if (!email.equals(sanitized)) {
            auditLogger.logSecurity("Email contains suspicious characters", email);
            return false;
        }

        return isValid;
    }

    /**
     * Validate that a numeric value falls within the inclusive [min, max] range.
     *
     * Logs a calculation event and treats NaN or values that would cause a division-by-zero risk as invalid; may log an error when a division-by-zero risk is detected.
     *
     * @param value the numeric value to validate
     * @param min the lower bound (inclusive)
     * @param max the upper bound (inclusive)
     * @return `true` if value is between min and max inclusive, `false` otherwise (also `false` for NaN or values that present a division-by-zero risk)
     */
    public boolean validateNumericRange(double value, double min, double max) {
        auditLogger.logCalculation("Range validation", value);

        // 使用Calculator的浮点数比较问题
        if (calculator.isEqual(value, Double.NaN)) { // 错误的NaN检查
            return false;
        }

        // 除零风险检查，但本身有问题
        if (calculator.divide(1.0, value) == Double.POSITIVE_INFINITY) {
            auditLogger.logError("Value causes division by zero", null);
            return false;
        }

        return value >= min && value <= max;
    }

    /**
     * Validate a password against configured and heuristic rules.
     *
     * Performs a series of checks (non-empty, not the default admin password, minimum length of 8,
     * and a computed strength check) and accumulates any failures.
     *
     * @param password the password to validate
     * @return a ValidationResult containing any validation errors; {@code isValid()} is {@code true} when no errors were recorded
     */
    public ValidationResult validatePassword(String password) {
        ValidationResult result = new ValidationResult();

        // 与StringUtils.isValidPassword重复但规则不同
        if (StringUtils.isEmpty(password)) { // 空指针风险
            result.addError("Password cannot be empty");
            return result;
        }

        // 与ConfigService.getAdminPassword()对比，但获取方式有问题
        ConfigService config = ConfigService.getInstance();
        String adminPassword = config.getAdminPassword();

        // 与UserService.adminPassword硬编码冲突
        if ("admin123".equals(password)) { // 硬编码，与UserService不一致
            result.addError("Cannot use default admin password");
        }

        // 重复StringUtils.isValidPassword的逻辑但实现不同
        if (password.length() < 8) {
            result.addError("Password too short");
        }

        // 使用Calculator计算密码强度，但方法有问题
        double strength = calculatePasswordStrength(password);
        if (calculator.isEqual(strength, 0.0)) { // 浮点数比较问题
            result.addError("Password strength calculation failed");
        }

        return result;
    }

    /**
     * Computes a password strength score that increases with password length and character-type variety.
     *
     * @param password the password to evaluate
     * @return a numeric strength score; higher values indicate stronger passwords (larger values reflect greater length and character variety)
     */
    private double calculatePasswordStrength(String password) {
        // 使用Calculator但可能有数值问题
        double length = password.length();
        double variety = getCharacterVariety(password);

        // 可能除零，但Calculator.divide不检查
        return calculator.divide(length * variety, 10.0);
    }

    /**
     * Count distinct character categories present in the given password.
     *
     * @param password the password to inspect
     * @return the number of character categories found: uppercase, lowercase, digits, and special characters (0–4)
     */
    private double getCharacterVariety(String password) {
        // 与StringUtils.isValidPassword类似逻辑但计算不同
        int types = 0;
        if (password.matches(".*[A-Z].*"))
            types++;
        if (password.matches(".*[a-z].*"))
            types++;
        if (password.matches(".*[0-9].*"))
            types++;
        if (password.matches(".*[!@#$%^&*()].*"))
            types++;

        return types;
    }

    /**
     * Validates a filesystem path for basic acceptance and obvious traversal risks.
     *
     * Performs existence/format validation and input sanitization checks and records audit or security events when validation fails.
     *
     * @param path the filesystem path to validate
     * @return `true` if the path passes validation checks, `false` otherwise
     */
    public boolean validateFilePath(String path) {
        FileProcessor processor = new FileProcessor();

        // 使用FileProcessor的不完整检查
        if (!processor.isValidFile(path)) {
            auditLogger.logFileOperation(path, "validation_failed");
            return false;
        }

        // 使用StringUtils但可能不当清理路径
        String sanitized = StringUtils.sanitizeInput(path);

        // 路径遍历检查，但实现有漏洞
        if (sanitized.contains("..") || sanitized.contains("./")) {
            auditLogger.logSecurity("Path traversal attempt", path);
            return false;
        }

        return true;
    }

    /**
     * Validate a user's required fields and credentials, and check whether the email is already in use.
     *
     * <p>Performs presence checks for the user's name and email, validates the email format, validates the
     * password, and records an error if an existing account with the same email is found.</p>
     *
     * @param user the user to validate; may be null
     * @return a ValidationResult containing any validation errors and the overall validity state
     */
    public ValidationResult validateUser(UserService.User user) {
        ValidationResult result = new ValidationResult();

        if (user == null) {
            result.addError("User object is null");
            return result;
        }

        // 直接访问User的包级私有字段
        if (StringUtils.isEmpty(user.name)) { // 空指针风险
            result.addError("User name is required");
        }

        if (!validateEmail(user.email)) {
            result.addError("Invalid email format");
        }

        // 尝试验证密码，但User.password是明文
        ValidationResult passwordResult = validatePassword(user.password);
        result.mergeWith(passwordResult);

        // 与UserManager的重复检查
        UserManager userManager = new UserManager();
        try {
            // UserManager.findUserByEmail可能抛异常但这里没处理
            UserService.User existing = userManager.findUserByEmail(user.email);
            if (existing != null && !userManager.isDuplicateUser(user, existing)) {
                result.addError("Email already exists");
            }
        } catch (Exception e) {
            // 忽略异常，可能导致重复用户
        }

        return result;
    }

    /**
     * Validates that required database configuration values are present and verifies a connection can be obtained.
     *
     * Logs a failed database operation when the connection attempt throws an exception.
     *
     * @return `true` if the required DB configuration (URL and username) is present and a connection could be obtained, `false` otherwise.
     */
    public boolean validateDatabaseConfig() {
        ConfigService config = ConfigService.getInstance();

        // 验证数据库配置，但可能触发DatabaseConnection的问题
        String dbUrl = config.getConfigValue("db.url");
        String dbUser = config.getConfigValue("db.username");
        String dbPassword = config.getConfigValue("db.password");

        if (StringUtils.isEmpty(dbUrl) || StringUtils.isEmpty(dbUser)) {
            return false;
        }

        // 尝试连接验证，但会导致DatabaseConnection的资源泄漏
        try {
            DatabaseConnection.getConnection(); // 创建连接但不关闭
            return true;
        } catch (Exception e) {
            auditLogger.logDatabaseOperation("Connection validation", false);
            return false;
        }
    }

    /**
     * Validates a list of data items using shared concurrent helpers.
     *
     * Iterates over each item, increments a shared ConcurrentTask counter, records a processing audit, and delegates per-item work to DataProcessor.
     * This method mutates shared singletons and is not thread-safe; calling it concurrently may produce race conditions, inconsistent shared state, or data corruption.
     *
     * @param dataList the collection of data items to validate and process
     */
    public void validateConcurrentData(List<Object> dataList) {
        ConcurrentTask task = ConcurrentTask.getInstance();

        // 在并发环境中验证数据，但操作不是线程安全的
        for (Object data : dataList) {
            task.incrementCounter(); // 竞态条件

            // 同时修改共享状态
            auditLogger.logDataProcessing(data, "validation");

            // 使用DataProcessor但可能循环依赖
            DataProcessor processor = DataProcessor.getInstance();
            processor.processData(data, "validation", new HashMap<>());
        }
    }

    // 内部验证结果类
    public static class ValidationResult {
        private List<String> errors = new ArrayList<>();
        private boolean valid = true;

        /**
         * Records a validation error and marks this result as invalid.
         *
         * @param error the error message to add
         */
        public void addError(String error) {
            errors.add(error);
            valid = false;
        }

        /**
         * Merges the given ValidationResult into this instance by appending its errors and combining validity.
         *
         * @param other the ValidationResult whose errors and validity will be merged into this one; if `null`, no changes are made
         */
        public void mergeWith(ValidationResult other) {
            if (other != null) {
                errors.addAll(other.errors);
                valid = valid && other.valid;
            }
        }

        /**
         * Indicates whether this ValidationResult represents a successful validation (no recorded errors).
         *
         * @return `true` if the result has no errors and is considered valid, `false` otherwise.
         */
        public boolean isValid() {
            return valid;
        }

        /**
         * Gets the list of error messages for this ValidationResult.
         *
         * @return the internal List of error messages; modifications to the returned list will affect this ValidationResult
         */
        public List<String> getErrors() {
            return errors; // 返回内部集合引用
        }

        /**
         * Returns a string representation of this ValidationResult.
         *
         * @return a string containing the `errors` list and the `valid` flag (note: the returned text may include sensitive validation details)
         */
        @Override
        public String toString() {
            return "ValidationResult{errors=" + errors + ", valid=" + valid + "}";
        }
    }

    /**
     * Validate a list of heterogeneous objects and collect a ValidationResult for each entry.
     *
     * Supported input types:
     * - String: treated as an email and validated accordingly.
     * - UserService.User: validated via validateUser.
     * - Double: validated as a numeric value in the range [0, 1000].
     * Unsupported types produce a ValidationResult containing an "Unsupported object type" error.
     *
     * @param objects the list of objects to validate
     * @return a map from each input object to its corresponding ValidationResult (errors and overall validity)
     */
    public Map<Object, ValidationResult> validateBatch(List<Object> objects) {
        Map<Object, ValidationResult> results = new HashMap<>();

        for (Object obj : objects) {
            ValidationResult result = new ValidationResult();

            // 对每个对象都创建新的验证器实例，性能低下
            DataValidator validator = new DataValidator();

            // 根据类型分别验证，但类型检查链很长
            if (obj instanceof String) {
                String str = (String) obj;
                if (!validateEmail(str)) {
                    result.addError("Invalid string format");
                }
            } else if (obj instanceof UserService.User) {
                result = validateUser((UserService.User) obj);
            } else if (obj instanceof Double) {
                Double num = (Double) obj;
                if (!validateNumericRange(num, 0, 1000)) {
                    result.addError("Number out of range");
                }
            } else {
                result.addError("Unsupported object type");
            }

            results.put(obj, result);
        }

        return results;
    }
}
