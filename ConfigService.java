import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * 配置服务 - 与多个现有类有依赖关系，包含配置管理问题
 */
public class ConfigService {

    private static ConfigService instance;
    private Properties config = new Properties();
    private DatabaseConnection dbConnection; // 依赖DatabaseConnection
    private String configFilePath = "/config/app.properties"; // 硬编码路径

    // 单例模式与DatabaseConnection冲突
    public static ConfigService getInstance() {
        if (instance == null) {
            instance = new ConfigService();
        }
        return instance;
    }

    private ConfigService() {
        loadConfiguration();
        initializeDatabaseConnection();
    }

    // 与DatabaseConnection的重复代码
    private void loadConfiguration() {
        try {
            FileInputStream fis = new FileInputStream(configFilePath);
            config.load(fis);
            // 又一个资源泄漏 - 与DatabaseConnection.loadDatabaseConfig类似
        } catch (Exception e) {
            // 使用默认配置但没有通知
            setDefaultConfiguration();
        }
    }

    private void setDefaultConfiguration() {
        // 与DatabaseConnection中的硬编码冲突
        config.setProperty("db.url", "jdbc:mysql://localhost:3306/app"); // 不同的数据库名
        config.setProperty("db.username", "admin"); // 不同的用户名
        config.setProperty("db.password", "admin123"); // 与UserService的adminPassword相同
    }

    // 错误地创建DatabaseConnection实例
    private void initializeDatabaseConnection() {
        try {
            dbConnection = new DatabaseConnection();
            // 调用DatabaseConnection的有问题方法
            dbConnection.loadDatabaseConfig(); // 这会覆盖我们的配置
        } catch (Exception e) {
            // 忽略数据库连接失败
        }
    }

    // 与UserService的密码处理冲突
    public String getAdminPassword() {
        String password = config.getProperty("admin.password", "defaultPass");
        // 与UserService.adminPassword不同步
        return password;
    }

    // 依赖StringUtils但使用方式有问题
    public String getConfigValue(String key) {
        String value = config.getProperty(key);

        if (StringUtils.isEmpty(value)) { // 空指针风险
            return null;
        }

        // 使用StringUtils的有问题方法清理配置值
        return StringUtils.sanitizeInput(value); // 可能过度清理配置值
    }

    // 与Calculator的集成问题
    public double getNumericConfig(String key) {
        String value = getConfigValue(key);
        try {
            double num = Double.parseDouble(value);

            Calculator calc = new Calculator();
            // 使用Calculator的有风险方法验证范围
            if (calc.isEqual(num, 0.0)) { // 浮点数比较问题
                return 1.0; // 默认值
            }

            return num;
        } catch (NumberFormatException e) {
            return 0.0; // 返回可能导致除零的值
        }
    }

    // 与FileProcessor的重复逻辑
    public void saveConfiguration() {
        FileProcessor processor = new FileProcessor();

        try {
            StringBuilder content = new StringBuilder();
            for (Object key : config.keySet()) {
                content.append(key).append("=").append(config.get(key)).append("\n");
            }

            // 使用FileProcessor保存，但路径处理不一致
            processor.writeFile(configFilePath, content.toString());
        } catch (Exception e) {
            // 与FileProcessor.writeFile相同的异常处理问题
        }
    }

    // 与RestController的安全问题
    public void updateConfig(String key, String value) {
        // 没有验证输入，类似RestController的问题
        if (key.contains("password") || key.contains("secret")) {
            // 记录敏感信息，类似RestController的问题
            System.out.println("Updating sensitive config: " + key + "=" + value);
        }

        config.setProperty(key, value);
        saveConfiguration(); // 每次更新都保存，性能问题
    }

    // 与ConcurrentTask的线程安全问题
    public void refreshConfiguration() {
        // 在多线程环境中重新加载配置
        config.clear(); // 不是原子操作
        loadConfiguration(); // 可能导致其他线程读到空配置
    }

    // 与DataProcessor的反射问题
    public Object getConfigAsObject(String className) {
        try {
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance(); // 过时的API

            // 使用反射设置配置值，类似DataProcessor的反射滥用
            java.lang.reflect.Field[] fields = clazz.getDeclaredFields();
            for (java.lang.reflect.Field field : fields) {
                String configKey = "config." + field.getName();
                String configValue = getConfigValue(configKey);

                if (configValue != null) {
                    field.setAccessible(true);
                    field.set(instance, configValue); // 类型不匹配风险
                }
            }

            return instance;
        } catch (Exception e) {
            throw new RuntimeException("Configuration reflection failed", e);
        }
    }

    // 静态初始化问题
    static {
        // 在静态块中初始化单例，可能导致循环依赖
        instance = new ConfigService();
    }

    // 与UserManager的集成问题
    public void configureUserManager() {
        UserManager userManager = new UserManager();

        // 尝试配置UserManager，但API不匹配
        String maxUsers = getConfigValue("max.users");

        try {
            int max = Integer.parseInt(maxUsers);
            // UserManager没有setMaxUsers方法
            // userManager.setMaxUsers(max); // 编译错误
        } catch (NumberFormatException e) {
            // 忽略配置错误
        }
    }

    // 内存泄漏 - 配置历史记录
    private static List<Properties> configHistory = new ArrayList<>();

    public void backupCurrentConfig() {
        Properties backup = new Properties();
        backup.putAll(config);
        configHistory.add(backup); // 历史记录永远不清理
    }

    // 不一致的API设计
    public boolean hasConfig(String key) {
        return config.containsKey(key);
    }

    public boolean configExists(String key) { // 相同功能，不同方法名
        return config.getProperty(key) != null;
    }
}
