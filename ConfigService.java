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
     * Get the singleton ConfigService instance, creating it if one does not already exist.
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
     * Initializes the ConfigService by loading configuration from storage and establishing the database connection.
     */
    private ConfigService() {
        loadConfiguration();
        initializeDatabaseConnection();
    }

    /**
     * Loads configuration properties from the file specified by the service's
     * configFilePath into the in-memory Properties and replaces current values.
     * If any error occurs while reading the file, the method falls back to the
     * default configuration by calling setDefaultConfiguration().
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
     * Populate the in-memory configuration with built-in defaults for database connection.
     *
     * Sets the following properties on the internal Properties object:
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
     * Initializes the DatabaseConnection instance and attempts to load its configuration.
     *
     * <p>Sets the class's {@code dbConnection} field and calls the connection's configuration loader,
     * which may overwrite in-memory configuration properties. Any exceptions thrown while creating
     * or loading the database connection are suppressed.
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
     * Retrieve the configured admin password from this service's properties.
     *
     * @return the value of `admin.password` from the configuration, or "defaultPass" if the property is not set
     */
    public String getAdminPassword() {
        String password = config.getProperty("admin.password", "defaultPass");
        // 与UserService.adminPassword不同步
        return password;
    }

    /**
     * Retrieve the configuration value for the given key, returning a sanitized string or null if the key is missing or empty.
     *
     * @param key the configuration property name to look up
     * @return the configuration value for the key after basic sanitization, or null if the property is not present or empty
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
     * Retrieve a numeric configuration value for the given property key.
     *
     * Parses the configuration value as a double. If the parsed number is considered equal to 0.0, this method returns 1.0. If the value is missing or cannot be parsed as a number, this method returns 0.0.
     *
     * @param key the configuration property name to read
     * @return the parsed numeric value; `1.0` if the parsed value is equal to 0.0; `0.0` if parsing fails or the value is missing
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
     * Persist the current configuration properties to the configured file path.
     *
     * Writes each property as a `key=value` line to the service's configured file location.
     * Any exception raised while writing is caught and suppressed (no exception is propagated).
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
     * Update a configuration property and persist the change to the configured storage.
     *
     * Updates the in-memory property identified by {@code key} to {@code value}, persists the current
     * configuration to the configured file, and may print sensitive keys and values to standard output.
     * This method does not validate input and performs a full save on every invocation.
     *
     * @param key   the configuration key to update
     * @param value the new value for the configuration key
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
     * Reloads in-memory configuration from the configured file source.
     *
     * This method clears the current Properties and then loads configuration from persistent storage.
     * The operation is not atomic: other threads may observe an empty or partially reloaded configuration
     * while this method executes.
     */
    public void refreshConfiguration() {
        // 在多线程环境中重新加载配置
        config.clear(); // 不是原子操作
        loadConfiguration(); // 可能导致其他线程读到空配置
    }

    /**
     * Creates an instance of the specified class and populates its declared fields
     * with configuration values whose keys are formed as "config.<fieldName>".
     *
     * @param className the fully-qualified name of the class to instantiate
     * @return the newly created instance with string-valued fields set from configuration
     * @throws RuntimeException if the class cannot be loaded, instantiated, or if a field cannot be set
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
     * Attempts to configure a new UserManager's maximum users from the "max.users" configuration.
     *
     * If the configuration value cannot be parsed as an integer, the method ignores the error and leaves the UserManager unmodified.
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
     * Saves a copy of the current configuration into the in-memory history.
     *
     * The method creates a new Properties instance containing the current config entries
     * and appends it to the static configHistory list; entries already in configHistory
     * are not removed or pruned, so the history can grow without bound.
     */
    public void backupCurrentConfig() {
        Properties backup = new Properties();
        backup.putAll(config);
        configHistory.add(backup); // 历史记录永远不清理
    }

    /**
     * Checks whether the configuration contains the specified property key.
     *
     * @param key the property key to check in the configuration
     * @return `true` if the configuration contains the key, `false` otherwise
     */
    public boolean hasConfig(String key) {
        return config.containsKey(key);
    }

    /**
     * Checks whether a configuration property with the given key is present.
     *
     * @param key the configuration key to check
     * @return `true` if a property with the given key exists (its value may be empty), `false` otherwise
     */
    public boolean configExists(String key) { // 相同功能，不同方法名
        return config.getProperty(key) != null;
    }
}
