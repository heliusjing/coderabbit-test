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

    public DataValidator() {
        this.calculator = new Calculator();
        this.auditLogger = AuditLogger.getInstance();
        // emailPattern没有初始化！
    }

    // 与StringUtils.isValidEmail重复但实现不一致
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

    // 数值验证但使用Calculator的有问题方法
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

    // 密码验证与多个类的冲突
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

    private double calculatePasswordStrength(String password) {
        // 使用Calculator但可能有数值问题
        double length = password.length();
        double variety = getCharacterVariety(password);

        // 可能除零，但Calculator.divide不检查
        return calculator.divide(length * variety, 10.0);
    }

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

    // 文件验证依赖FileProcessor但加重其问题
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

    // 用户数据验证，依赖UserService和UserManager
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

    // 数据库连接配置验证
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

    // 并发验证但线程安全问题
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

        public void addError(String error) {
            errors.add(error);
            valid = false;
        }

        public void mergeWith(ValidationResult other) {
            if (other != null) {
                errors.addAll(other.errors);
                valid = valid && other.valid;
            }
        }

        public boolean isValid() {
            return valid;
        }

        public List<String> getErrors() {
            return errors; // 返回内部集合引用
        }

        // toString可能暴露敏感验证信息
        @Override
        public String toString() {
            return "ValidationResult{errors=" + errors + ", valid=" + valid + "}";
        }
    }

    // 批量验证但性能问题
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
