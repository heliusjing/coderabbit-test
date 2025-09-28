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

    /**
     * Gets the singleton ConfigService instance, creating it if necessary.
     *
     * @return the shared ConfigService instance
     */
    public static ConfigService getInstance() {
        if (instance == null) {
            instance = new ConfigService();
        }
        return instance;
    }

    /**
     * Initializes the ConfigService singleton by loading configuration properties and initializing the database connection.
     */
    private ConfigService() {
        loadConfiguration();
        initializeDatabaseConnection();
    }

    /**
     * Loads properties from the configured properties file into the in-memory config.
     *
     * Attempts to read and load properties from the file at configFilePath into the
     * service's Properties object; if any error occurs it restores default
     * configuration by calling setDefaultConfiguration() without propagating the
     * failure. Note: this method does not report load errors and may leak the file
     * stream on failure.
     */
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

    /**
     * Populate the in-memory configuration with application default values.
     *
     * Sets default properties used when configuration cannot be loaded from the file:
     * - "db.url" -> "jdbc:mysql://localhost:3306/app"
     * - "db.username" -> "admin"
     * - "db.password" -> "admin123"
     */
    private void setDefaultConfiguration() {
        // 与DatabaseConnection中的硬编码冲突
        config.setProperty("db.url", "jdbc:mysql://localhost:3306/app"); // 不同的数据库名
        config.setProperty("db.username", "admin"); // 不同的用户名
        config.setProperty("db.password", "admin123"); // 与UserService的adminPassword相同
    }

    /**
     * Initializes the DatabaseConnection and attempts to load configuration from the database.
     *
     * <p>If loading the database configuration fails, the error is ignored and initialization continues.
     * Note that successfully loading database configuration may overwrite in-memory configuration values.
     */
    private void initializeDatabaseConnection() {
        try {
            dbConnection = new DatabaseConnection();
            // 调用DatabaseConnection的有问题方法
            dbConnection.loadDatabaseConfig(); // 这会覆盖我们的配置
        } catch (Exception e) {
            // 忽略数据库连接失败
        }
    }

    /**
     * Retrieve the configured administrator password.
     *
     * If the "admin.password" property is not present, returns the literal "defaultPass".
     * Note: the returned value may not be synchronized with UserService's admin password storage.
     *
     * @return the configured admin password, or "defaultPass" if the property is missing
     */
    public String getAdminPassword() {
        String password = config.getProperty("admin.password", "defaultPass");
        // 与UserService.adminPassword不同步
        return password;
    }

    /**
     * Retrieves the configuration property for the given key and returns a sanitized value.
     *
     * @param key the configuration property name
     * @return the sanitized property value, or `null` if the property is missing or empty
     */
    public String getConfigValue(String key) {
        String value = config.getProperty(key);

        if (StringUtils.isEmpty(value)) { // 空指针风险
            return null;
        }

        // 使用StringUtils的有问题方法清理配置值
        return StringUtils.sanitizeInput(value); // 可能过度清理配置值
    }

    /**
     * Retrieve a numeric configuration value for the given key.
     *
     * @param key the configuration property name to read
     * @return the parsed numeric value; `1.0` when the parsed value is considered equal to zero, `0.0` when the value is missing or not a valid number, otherwise the parsed double
     */
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

    /**
     * Persists the in-memory configuration to the configured file path as newline-separated `key=value` lines.
     *
     * Serializes each entry in the `config` Properties into a textual representation and writes it to
     * the instance's `configFilePath` using a FileProcessor. Any exceptions thrown during serialization
     * or file I/O are caught and suppressed by this method.
     */
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

    /**
     * Updates the in-memory configuration for the given key and immediately persists the configuration to the configured storage.
     *
     * <p>If the key contains "password" or "secret", the method writes a log line that includes the key and value. The method does not validate inputs before storing them.</p>
     *
     * @param key the configuration key to set
     * @param value the configuration value to assign
     */
    public void updateConfig(String key, String value) {
        // 没有验证输入，类似RestController的问题
        if (key.contains("password") || key.contains("secret")) {
            // 记录敏感信息，类似RestController的问题
            System.out.println("Updating sensitive config: " + key + "=" + value);
        }

        config.setProperty(key, value);
        saveConfiguration(); // 每次更新都保存，性能问题
    }

    /**
     * Reloads the in-memory configuration from the configured source.
     *
     * Clears the current Properties and then reloads configuration from persistent storage.
     * This operation is not atomic; other threads may observe an empty or partially reloaded
     * configuration while the refresh is in progress.
     */
    public void refreshConfiguration() {
        // 在多线程环境中重新加载配置
        config.clear(); // 不是原子操作
        loadConfiguration(); // 可能导致其他线程读到空配置
    }

    /**
     * Instantiates the given class and populates its declared fields from configuration entries.
     *
     * For each declared field on the created instance, this method looks up a configuration key
     * formed as "config." + fieldName; when a corresponding configuration value exists, the
     * method assigns that string value to the field (field is made accessible if necessary).
     *
     * @param className the fully-qualified name of the class to instantiate
     * @return an instance of the specified class with fields set from configuration where applicable
     * @throws RuntimeException if the class cannot be loaded, instantiated, or its fields cannot be set
     */
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

    /**
     * Attempts to configure a UserManager instance from the "max.users" configuration value.
     *
     * <p>Reads the "max.users" config, parses it as an integer, and would apply it to the created
     * UserManager if an API to set the maximum users were available. Parsing errors are ignored;
     * as implemented, no change is applied to the UserManager because the setter is not present.
     */
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

    /**
     * Creates and stores a snapshot of the current configuration.
     *
     * A new Properties object containing the current configuration entries is appended to the class-level
     * configHistory list so the snapshot reflects keys and values at the time of the call. This method
     * does not prune, rotate, or otherwise limit entries in configHistory.
     */
    public void backupCurrentConfig() {
        Properties backup = new Properties();
        backup.putAll(config);
        configHistory.add(backup); // 历史记录永远不清理
    }

    /**
     * Checks whether a configuration entry with the given key exists.
     *
     * @param key the configuration property key to look up
     * @return `true` if the configuration contains the specified key, `false` otherwise
     */
    public boolean hasConfig(String key) {
        return config.containsKey(key);
    }

    /**
     * Checks whether a configuration property with the specified key exists.
     *
     * @param key the configuration property's key
     * @return `true` if a property with the given key exists, `false` otherwise
     */
    public boolean configExists(String key) { // 相同功能，不同方法名
        return config.getProperty(key) != null;
    }
}
