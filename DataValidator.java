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
     * Constructs a DataValidator and initializes its Calculator and AuditLogger instances.
     *
     * The constructor does not initialize the emailPattern field. */
    public DataValidator() {
        this.calculator = new Calculator();
        this.auditLogger = AuditLogger.getInstance();
        // emailPattern没有初始化！
    }

    /**
     * Validates an email string for basic format and rejects empty or sanitized-altered inputs.
     *
     * @param email the email to validate; null or empty inputs are treated as invalid
     * @return `true` if the email matches the class's `EMAIL_REGEX` and is unchanged by sanitization, `false` otherwise
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
     * Checks whether a numeric value lies within the inclusive range [min, max] after basic sanity checks.
     *
     * <p>Performs sanity checks for invalid numeric inputs before evaluating the range: values that are
     * detected as NaN or that trigger a division-by-zero check are treated as invalid.</p>
     *
     * @param value the numeric value to validate
     * @param min   the lower bound (inclusive)
     * @param max   the upper bound (inclusive)
     * @return `true` if the value passes sanity checks and is between `min` and `max` (inclusive), `false` otherwise
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
     * Validate a candidate password against configured rules and policy checks.
     *
     * <p>Performs these checks: non-empty, rejects the known default admin password, enforces a minimum
     * length of 8 characters, and verifies a non-zero strength score computed by the validator.
     *
     * @param password the password to validate; may be null or empty
     * @return a ValidationResult containing any validation errors; {@code isValid()} is true when no errors were recorded
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
     * Calculates a password strength score proportional to the product of the password's length
     * and its character-class variety, scaled by 10.
     *
     * @param password the password to evaluate
     * @return the strength score computed as (length * character variety) / 10
     */
    private double calculatePasswordStrength(String password) {
        // 使用Calculator但可能有数值问题
        double length = password.length();
        double variety = getCharacterVariety(password);

        // 可能除零，但Calculator.divide不检查
        return calculator.divide(length * variety, 10.0);
    }

    /**
     * Determines how many distinct character classes the password contains.
     *
     * Counts presence of these classes: uppercase letters, lowercase letters, digits, and the special characters !@#$%^&*().
     *
     * @return the number of character classes present in the password (0–4)
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
     * Validates a filesystem path for basic file validity and simple path-traversal patterns.
     *
     * This method uses a FileProcessor check, sanitizes the input, and rejects paths that contain
     * the sequences ".." or "./" after sanitization. On validation failure it records audit events.
     *
     * @param path the file path to validate
     * @return `true` if the path passes FileProcessor validation and does not contain "`..`" or "`./`" after sanitization, `false` otherwise
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
     * Validates a User object's fields and uniqueness, aggregating any validation errors.
     *
     * This performs these checks and records corresponding errors in the returned result:
     * - null user object (adds "User object is null")
     * - missing or empty user name (adds "User name is required")
     * - invalid email format (adds "Invalid email format")
     * - password validation problems (merges errors produced by validatePassword)
     * - existing user with the same email (adds "Email already exists")
     *
     * Lookup errors that occur while checking for an existing user are ignored and do not throw.
     *
     * @param user the UserService.User to validate; may be null
     * @return a ValidationResult containing all discovered validation errors; the result is valid when no errors were added
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
     * Validates database connection configuration and attempts a test connection.
     *
     * Checks that the configured database URL and username are present; if so, attempts to obtain a database connection to verify connectivity. Logs a database operation and returns `false` if the connection attempt fails.
     *
     * @return `true` if required DB configuration is present and a connection could be obtained, `false` otherwise.
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
     * Validates each item in the provided list by incrementing a shared task counter, logging processing, and delegating validation to the DataProcessor.
     *
     * This method mutates shared state (the singleton ConcurrentTask counter), calls the audit logger for each item, and invokes DataProcessor.processData with a new empty map for each element. The implementation is not thread-safe and may produce race conditions when used concurrently.
     *
     * @param dataList the list of objects to validate; each element will be processed as a validation task
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
         * Records a validation error and marks the result as invalid.
         *
         * Adds the provided error message to the internal error list and sets the validity flag to false.
         *
         * @param error the error message to record
         */
        public void addError(String error) {
            errors.add(error);
            valid = false;
        }

        /**
         * Merges another ValidationResult into this one, combining their error lists and validity.
         *
         * After merging, this instance's errors include all errors from the other result and its
         * valid flag is the logical AND of the two results' valid flags.
         *
         * @param other the ValidationResult to merge into this one; if null, this method does nothing
         */
        public void mergeWith(ValidationResult other) {
            if (other != null) {
                errors.addAll(other.errors);
                valid = valid && other.valid;
            }
        }

        /**
         * Indicates whether this ValidationResult has no recorded validation errors.
         *
         * @return `true` if the ValidationResult is valid (no recorded errors), `false` otherwise.
         */
        public boolean isValid() {
            return valid;
        }

        /**
         * Get the list of validation error messages.
         *
         * This returns a direct reference to the internal mutable list; modifying the returned list
         * will modify this ValidationResult's error collection.
         *
         * @return the internal {@code List<String>} of error messages
         */
        public List<String> getErrors() {
            return errors; // 返回内部集合引用
        }

        /**
         * String representation of the ValidationResult containing its error list and validity flag.
         *
         * @return a string that includes the `errors` list and the `valid` flag; this representation may expose sensitive validation details
         */
        @Override
        public String toString() {
            return "ValidationResult{errors=" + errors + ", valid=" + valid + "}";
        }
    }

    /**
     * Performs validation over a list of heterogeneous objects and collects a ValidationResult for each item.
     *
     * Validates items by type: Strings are validated as emails, UserService.User objects are fully validated, Doubles are checked to be in the range [0, 1000], and other types produce an "Unsupported object type" error. Each input object is mapped to its corresponding ValidationResult containing any validation errors and an overall validity flag.
     *
     * @param objects the list of objects to validate
     * @return a map from each original input object to its accumulated ValidationResult
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
