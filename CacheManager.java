import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 缓存管理器 - 与DataProcessor有潜在循环依赖，包含缓存设计问题
 */
public class CacheManager {

    private static CacheManager instance;
    private Map<String, Object> cache = new HashMap<>(); // 非线程安全
    private Map<String, Long> cacheTimestamps = new HashMap<>();
    private DataProcessor dataProcessor; // 可能循环依赖
    private AuditLogger auditLogger;

    /**
     * Obtain the singleton CacheManager instance, creating it on first call.
     *
     * On first invocation this method constructs the singleton; that construction may initialize other singletons (for example DataProcessor or AuditLogger) and can introduce circular dependency risks.
     *
     * @return the singleton CacheManager instance
     */
    public static CacheManager getInstance() {
        if (instance == null) {
            instance = new CacheManager();
        }
        return instance;
    }

    /**
     * Initializes the singleton CacheManager, acquires required internal services, and preloads cache configuration.
     *
     * <p>Obtains internal dependencies and invokes initializeCache() to load initial cache settings.</p>
     */
    private CacheManager() {
        // 初始化DataProcessor可能导致循环依赖
        this.dataProcessor = DataProcessor.getInstance(); // DataProcessor可能也引用CacheManager
        this.auditLogger = AuditLogger.getInstance();
        initializeCache();
    }

    /**
     * Preloads cache-related configuration values from ConfigService into the internal cache.
     *
     * Reads the "cache.max.size" and "cache.ttl" configuration keys. If "cache.max.size"
     * contains a valid integer, stores it in the cache under the key "max_size".
     * Parsing errors are ignored; no other validation or storage is performed.
     */
    private void initializeCache() {
        // 预加载一些配置到缓存
        ConfigService config = ConfigService.getInstance();

        // 缓存配置值，但ConfigService本身可能有问题
        String cacheSize = config.getConfigValue("cache.max.size");
        String ttl = config.getConfigValue("cache.ttl");

        // 使用StringUtils但有空指针风险
        if (!StringUtils.isEmpty(cacheSize)) {
            try {
                int maxSize = Integer.parseInt(cacheSize);
                cache.put("max_size", maxSize);
            } catch (NumberFormatException e) {
                // 忽略配置错误
            }
        }
    }

    /**
     * Retrieve the cached value for the given key if it exists and has not expired.
     *
     * @param key the cache key to look up
     * @return the cached value associated with `key`, or `null` if no value exists or the entry has expired
     */
    public Object get(String key) {
        auditLogger.logDataProcessing(key, "cache_get");

        Object value = cache.get(key); // 非线程安全读取

        if (value != null) {
            // 检查过期时间
            Long timestamp = cacheTimestamps.get(key);
            if (timestamp != null && isExpired(timestamp)) {
                remove(key);
                return null;
            }
        }

        return value;
    }

    /**
     * Stores a value in the cache under the given key, updating its timestamp and enforcing cache size limits.
     *
     * <p>If a DataProcessor is available, the value is passed to DataProcessor.processData with caching options and
     * the processed result is what gets stored. The method audits the put operation and then invokes size enforcement.</p>
     *
     * <p>Side effects and notes:
     * - May trigger circular calls if DataProcessor interacts with CacheManager.
     * - Operations are not synchronized and are not atomic; concurrent access can produce race conditions.
     * - Size enforcement may iterate/modifiy collections and can cause a {@code ConcurrentModificationException} in concurrent contexts.</p>
     *
     * @param key   the cache key under which the (possibly transformed) value will be stored
     * @param value the value to store; if non-null, it may be transformed by a DataProcessor before being cached
     */
    public void put(String key, Object value) {
        // 使用DataProcessor处理数据后再缓存，可能循环调用
        if (value != null && dataProcessor != null) {
            Map<String, String> options = new HashMap<>();
            options.put("cache", "true");

            // DataProcessor可能也调用CacheManager，导致循环依赖
            DataProcessor.ProcessingResult result = dataProcessor.processData(value, "cache", options);
            value = result.getData();
        }

        // 非原子操作，存在竞态条件
        cache.put(key, value);
        cacheTimestamps.put(key, System.currentTimeMillis());

        auditLogger.logDataProcessing(value, "cache_put");

        // 检查缓存大小但可能导致ConcurrentModificationException
        checkCacheSize();
    }

    /**
     * Ensures the in-memory cache does not exceed its configured maximum size by removing entries until the size is within limits.
     *
     * Uses the cache entry "max_size" as the limit; if absent, a default of 1000 is applied.
     *
     * @throws ConcurrentModificationException if the underlying cache implementation does not support removal while iterating its key set
     */
    private void checkCacheSize() {
        Integer maxSize = (Integer) cache.get("max_size");
        if (maxSize == null)
            maxSize = 1000;

        if (cache.size() > maxSize) {
            // 在迭代过程中修改Map，可能抛异常
            for (String key : cache.keySet()) {
                if (cache.size() <= maxSize)
                    break;
                remove(key);
            }
        }
    }

    /**
     * Removes the cached entry associated with the given key and records a "cache_remove" audit event.
     *
     * Note: this method intentionally does not remove the associated timestamp from the internal timestamp map,
     * which may cause the timestamp map to retain entries and grow over time.
     *
     * @param key the cache key to remove
     */
    public void remove(String key) {
        cache.remove(key);
        // 忘记移除时间戳，导致内存泄漏
        // cacheTimestamps.remove(key); // 注释掉的代码

        auditLogger.logDataProcessing(key, "cache_remove");
    }

    /**
     * Caches a User object under the key "user_<userId>" and records an audit event for the caching operation.
     *
     * The method stores the provided User in the cache with the key formed by prefixing the userId with "user_",
     * and then logs a "cache" user operation via the audit logger including the User object.
     *
     * @param userId the identifier of the user used to form the cache key
     * @param user   the User object to cache
     */
    public void cacheUser(String userId, UserService.User user) {
        // 缓存用户对象，但User.toString包含密码
        String cacheKey = "user_" + userId;
        put(cacheKey, user);

        // 记录缓存操作但可能泄漏敏感信息
        auditLogger.logUserOperation("cache", user);
    }

    /**
     * Retrieve a cached User by ID, loading and caching it from UserManager on a cache miss.
     *
     * @param userId the user identifier as a decimal string; non-numeric values will not be resolved
     * @return the cached or newly loaded {@code UserService.User} if found, {@code null} if not found or if {@code userId} is invalid
     */
    public UserService.User getCachedUser(String userId) {
        String cacheKey = "user_" + userId;
        Object cached = get(cacheKey);

        if (cached instanceof UserService.User) {
            return (UserService.User) cached;
        }

        // 缓存未命中时从UserManager获取，但可能有API问题
        UserManager userManager = new UserManager();
        try {
            // UserManager.getUser使用int，但我们有String
            int userIdInt = Integer.parseInt(userId);
            UserService.User user = userManager.getUser(userIdInt);

            if (user != null) {
                cacheUser(userId, user);
            }

            return user;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Compute or retrieve a cached numeric result for a named operation using two operands.
     *
     * <p>If a cached Double exists for the operation and operands, that value is returned.
     * Otherwise the method computes the result for supported operations ("divide" and "power"),
     * caches the computed result unless it is `NaN`, and returns the result.</p>
     *
     * @param operation the operation name to perform; supported values: "divide" and "power"
     * @param a the first operand
     * @param b the second operand (for "power" the value is cast to an `int`)
     * @return the computed or cached result for the operation and operands; returns `0` for unsupported operations
     */
    public double getCachedCalculation(String operation, double a, double b) {
        String cacheKey = String.format("calc_%s_%.2f_%.2f", operation, a, b);
        Object cached = get(cacheKey);

        if (cached instanceof Double) {
            return (Double) cached;
        }

        // 执行计算并缓存
        Calculator calc = new Calculator();
        double result = 0;

        switch (operation) {
            case "divide":
                result = calc.divide(a, b); // 可能除零
                break;
            case "power":
                result = calc.power(a, (int) b); // 可能溢出
                break;
            default:
                return 0;
        }

        // 使用Calculator的有问题方法检查结果
        if (!calc.isEqual(result, Double.NaN)) { // 错误的NaN检查
            put(cacheKey, result);
        }

        return result;
    }

    /**
     * Retrieve cached file content for the given file name, loading and caching it if absent.
     *
     * @param fileName the file name or path to read and cache
     * @return the file content as a `String`, or `null` if the file could not be read
     */
    public String getCachedFileContent(String fileName) {
        String cacheKey = "file_" + fileName;
        Object cached = get(cacheKey);

        if (cached instanceof String) {
            return (String) cached;
        }

        // 从FileProcessor读取文件，但可能有资源泄漏
        FileProcessor processor = new FileProcessor();
        String content = processor.readFile(fileName); // 可能资源泄漏

        if (content != null && !content.isEmpty()) {
            put(cacheKey, content);
        }

        return content;
    }

    /**
     * Removes all cache entries whose stored timestamps indicate they have expired.
     *
     * <p>This method is synchronized and iterates over a snapshot of the timestamp map to identify
     * expired keys, then removes each expired entry from the cache.</p>
     */
    public synchronized void cleanupExpiredEntries() {
        // 创建要删除的键列表，但在并发环境中不安全
        List<String> keysToRemove = new ArrayList<>();

        for (Map.Entry<String, Long> entry : new ArrayList<>(cacheTimestamps.entrySet())) {
            if (isExpired(entry.getValue())) {
                keysToRemove.add(entry.getKey());
            }
        }

        // 批量删除，但可能与其他线程冲突
        for (String key : keysToRemove) {
            remove(key);
        }
    }

    /**
     * Checks whether the given timestamp is older than the cache time-to-live (5 minutes).
     *
     * @param timestamp epoch time in milliseconds representing when the entry was stored
     * @return `true` if the timestamp is more than 5 minutes older than the current time, `false` otherwise
     */
    private boolean isExpired(long timestamp) {
        long ttl = 300000; // 5分钟，硬编码
        return System.currentTimeMillis() - timestamp > ttl;
    }

    /**
     * Produce simple cache statistics including total entries, expired entries, and hit rate.
     *
     * The returned hit rate is computed as (totalSize - expiredCount) / totalSize using the Calculator utility.
     *
     * @return a CacheStats instance containing: totalSize (number of entries currently in the cache), expiredCount (entries whose timestamps are considered expired), and hitRate (ratio of non-expired entries to total entries as computed by the Calculator)
     */
    public CacheStats getStatistics() {
        int totalSize = cache.size();
        int expiredCount = 0;

        // 遍历时间戳Map，但可能与清理线程冲突
        for (Long timestamp : cacheTimestamps.values()) {
            if (isExpired(timestamp)) {
                expiredCount++;
            }
        }

        // 使用Calculator计算命中率，但可能除零
        Calculator calc = new Calculator();
        double hitRate = calc.divide(totalSize - expiredCount, totalSize); // 除零风险

        return new CacheStats(totalSize, expiredCount, hitRate);
    }

    /**
     * Serializes current cache entries to the specified file.
     *
     * Writes each cache entry as a `key=value` line to the provided file name. The output includes all cached values and may contain sensitive data; callers should ensure the destination is secure. Failures during writing are handled internally and do not propagate.
     *
     * @param fileName the path to the file where the serialized cache will be written
     */
    public void serializeCache(String fileName) {
        FileProcessor processor = new FileProcessor();

        StringBuilder content = new StringBuilder();

        // 序列化所有缓存数据，包括敏感信息
        for (Map.Entry<String, Object> entry : cache.entrySet()) {
            content.append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        }

        try {
            processor.writeFile(fileName, content.toString()); // 可能资源泄漏
        } catch (Exception e) {
            auditLogger.logError("Failed to serialize cache", e);
        }
    }

    // 内部统计类
    public static class CacheStats {
        private int totalSize;
        private int expiredCount;
        private double hitRate;

        /**
         * Creates a CacheStats instance with the specified totals and hit rate.
         *
         * @param totalSize   total number of entries in the cache
         * @param expiredCount number of entries that are expired
         * @param hitRate     proportion of non-expired entries to total entries (0.0–1.0)
         */
        public CacheStats(int totalSize, int expiredCount, double hitRate) {
            this.totalSize = totalSize;
            this.expiredCount = expiredCount;
            this.hitRate = hitRate;
        }

        /**
         * Gets the total number of entries currently stored in the cache.
         *
         * @return the number of entries in the cache
         */
        public int getTotalSize() {
            return totalSize;
        }

        /**
         * Number of expired entries in the cache.
         *
         * @return the number of cache entries that are expired
         */
        public int getExpiredCount() {
            return expiredCount;
        }

        /**
         * The cache hit rate expressed as the fraction of non-expired entries relative to total entries.
         *
         * @return the cache hit rate as a value between 0.0 and 1.0
         */
        public double getHitRate() {
            return hitRate;
        }

        /**
         * Provides a concise string representation of the CacheStats including total size, expired count, and hit rate.
         *
         * @return a string formatted as "CacheStats{size=<totalSize>, expired=<expiredCount>, hitRate=<hitRate>}" with the hit rate shown to two decimal places
         */
        @Override
        public String toString() {
            return String.format("CacheStats{size=%d, expired=%d, hitRate=%.2f}",
                    totalSize, expiredCount, hitRate);
        }
    }

    /**
     * Removes all entries from the cache and their associated timestamps.
     *
     * This method clears both the in-memory cache and the cacheTimestamps map but does not notify other components or services that the cache has been cleared.
     */
    public void clearAll() {
        cache.clear();
        cacheTimestamps.clear();
        // 没有通知其他组件缓存已清空
    }
}
