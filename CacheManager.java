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
     * Get the singleton CacheManager instance.
     *
     * May initialize the singleton lazily on first call; this can create a circular dependency
     * if other singletons accessed during initialization reference CacheManager.
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
     * Initializes the CacheManager singleton by resolving required components and preloading cache configuration.
     *
     * Acquires the DataProcessor and AuditLogger singletons and invokes initializeCache() to populate initial
     * cache entries. Note: obtaining the DataProcessor here may create a circular dependency if DataProcessor
     * also references CacheManager.
     */
    private CacheManager() {
        // 初始化DataProcessor可能导致循环依赖
        this.dataProcessor = DataProcessor.getInstance(); // DataProcessor可能也引用CacheManager
        this.auditLogger = AuditLogger.getInstance();
        initializeCache();
    }

    /**
     * Preloads cache-related configuration from the ConfigService into the in-memory cache.
     *
     * <p>Retrieves the "cache.max.size" configuration and, if it can be parsed as an integer,
     * stores that integer under the "max_size" cache key. Invalid or unparseable values are ignored.
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
     * Retrieve the cached value for the given key if present and not expired.
     *
     * @param key the cache key
     * @return the cached value for the key, or `null` if no value is stored or the entry has expired
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
     * Stores a value in the cache under the given key, optionally transforming it via the configured DataProcessor before insertion.
     *
     * If a DataProcessor is available, the value is passed to it and the returned data is what gets cached. The method updates the cache map and its timestamp, logs the operation via the AuditLogger, and invokes a size check to enforce the configured maximum.
     *
     * Note: this operation is not thread-safe, may exhibit race conditions, and the use of an external DataProcessor can lead to circular calls back into the cache. The subsequent size-check may trigger runtime errors (e.g., ConcurrentModificationException) in concurrent environments.
     *
     * @param key   the cache key under which to store the value
     * @param value the value to cache; if non-null and a DataProcessor is configured, this value may be transformed before storage
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
     * Ensures the cache does not exceed the configured maximum size by removing entries until the size is within limit.
     *
     * Reads the maximum size from the cache under the "max_size" key and uses 1000 if absent; iterates over keys and
     * removes entries until cache.size() <= maxSize. Removal order is unspecified.
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
     * Removes the cached value associated with the given key and records the removal with the audit logger.
     *
     * Note: this method does not remove the corresponding entry from cacheTimestamps, so the timestamp map may retain an entry for the key.
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
     * Cache a user object under a deterministic key and record the caching operation.
     *
     * Caches the given UserService.User using the key "user_<userId>" and logs the cache action via the audit logger.
     * Note: the cached object's string representation and the audit log entry may include sensitive information (for example, passwords) depending on the User implementation.
     *
     * @param userId the identifier for the user, used to build the cache key "user_<userId>"
     * @param user   the UserService.User instance to cache
     */
    public void cacheUser(String userId, UserService.User user) {
        // 缓存用户对象，但User.toString包含密码
        String cacheKey = "user_" + userId;
        put(cacheKey, user);

        // 记录缓存操作但可能泄漏敏感信息
        auditLogger.logUserOperation("cache", user);
    }

    /**
     * Retrieve a User by ID from the cache, loading and caching it from UserManager on a cache miss.
     *
     * @param userId the user identifier as a string (expected to parse as an integer)
     * @return the cached or loaded UserService.User, or `null` if the user is not found or `userId` cannot be parsed as an integer
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
     * Retrieves a cached calculation result for the given operation and operands, computing and caching the result if not present.
     *
     * @param operation the operation to perform; supported values are "divide" and "power" (any other value causes the method to return 0)
     * @param a the first operand
     * @param b the second operand
     * @return the cached or newly computed result for the requested operation; returns 0 for unsupported operations
     *
     * Note: when a result is computed it is stored in the cache under a key derived from the operation and operands only if
     * Calculator.isEqual(result, Double.NaN) returns false (this method does not correctly detect NaN). Division and exponentiation
     * are delegated to Calculator and may exhibit calculator-specific behavior (for example, division by zero or overflow). 
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
     * Retrieves the content of the named file from the cache, or reads it from disk and caches it when found.
     *
     * @param fileName the name or path of the file to retrieve
     * @return the file content as a String, or {@code null} if the file could not be read or does not exist
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
     * Removes entries from the cache whose timestamps indicate they have expired.
     *
     * This method scans the current cache timestamp snapshot, collects keys whose timestamps
     * return true for {@code isExpired(long)}, and removes those entries from the cache by
     * invoking {@code remove(String)}.
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
     * Checks whether a cached entry's timestamp is older than the configured time-to-live (5 minutes).
     *
     * @param timestamp epoch millisecond timestamp representing when the entry was stored
     * @return `true` if the timestamp is older than 5 minutes (300000 ms), `false` otherwise
     */
    private boolean isExpired(long timestamp) {
        long ttl = 300000; // 5分钟，硬编码
        return System.currentTimeMillis() - timestamp > ttl;
    }

    /**
     * Compute summary statistics for the cache.
     *
     * <p>Counts total entries and how many timestamps in {@code cacheTimestamps} are considered expired.
     * The hit rate is calculated as (totalSize - expiredCount) / totalSize and may be undefined when
     * {@code totalSize} is zero.
     *
     * @return a CacheStats object containing total size, expired count, and hit rate
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
     * Serializes all cache entries to the specified file as newline-separated `key=value` lines.
     *
     * This writes every entry from the in-memory cache to disk and may therefore expose sensitive
     * information stored in the cache. Failures during writing are caught and recorded via the
     * AuditLogger; this method does not propagate I/O exceptions.
     *
     * @param fileName the path to the file to write the serialized cache to
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
         * Creates a CacheStats instance representing the current cache metrics.
         *
         * @param totalSize   the total number of entries currently tracked in the cache
         * @param expiredCount the number of tracked entries that are expired
         * @param hitRate     the cache hit rate as a fraction between 0.0 and 1.0
         */
        public CacheStats(int totalSize, int expiredCount, double hitRate) {
            this.totalSize = totalSize;
            this.expiredCount = expiredCount;
            this.hitRate = hitRate;
        }

        /**
         * Total number of entries currently tracked in the cache.
         *
         * @return the total number of entries in the cache
         */
        public int getTotalSize() {
            return totalSize;
        }

        /**
         * Number of expired cache entries.
         *
         * @return the number of expired entries in the cache
         */
        public int getExpiredCount() {
            return expiredCount;
        }

        /**
         * Gets the cache hit rate.
         *
         * @return the cache hit rate as a fraction (non-expired entries divided by total entries), typically between 0 and 1
         */
        public double getHitRate() {
            return hitRate;
        }

        /**
         * Produces a string representation of the cache statistics.
         *
         * @return a string formatted as "CacheStats{size=<totalSize>, expired=<expiredCount>, hitRate=<hitRate>}"
         */
        @Override
        public String toString() {
            return String.format("CacheStats{size=%d, expired=%d, hitRate=%.2f}",
                    totalSize, expiredCount, hitRate);
        }
    }

    /**
     * Removes all entries from the cache and from the cache timestamp store.
     *
     * <p>This clears the in-memory cache and the associated timestamp map. It does not notify
     * other components or perform any additional cleanup (for example, it does not trigger
     * eviction hooks or remove external references), so callers should handle any required
     * notifications or side effects separately.
     */
    public void clearAll() {
        cache.clear();
        cacheTimestamps.clear();
        // 没有通知其他组件缓存已清空
    }
}
