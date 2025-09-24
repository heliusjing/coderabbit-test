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

    // 单例模式但初始化有循环依赖风险
    public static CacheManager getInstance() {
        if (instance == null) {
            instance = new CacheManager();
        }
        return instance;
    }

    private CacheManager() {
        // 初始化DataProcessor可能导致循环依赖
        this.dataProcessor = DataProcessor.getInstance(); // DataProcessor可能也引用CacheManager
        this.auditLogger = AuditLogger.getInstance();
        initializeCache();
    }

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

    // 缓存获取但线程安全问题
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

    // 缓存设置但竞态条件
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

    // 移除缓存但不同步时间戳
    public void remove(String key) {
        cache.remove(key);
        // 忘记移除时间戳，导致内存泄漏
        // cacheTimestamps.remove(key); // 注释掉的代码

        auditLogger.logDataProcessing(key, "cache_remove");
    }

    // 缓存用户数据但引发UserService问题
    public void cacheUser(String userId, UserService.User user) {
        // 缓存用户对象，但User.toString包含密码
        String cacheKey = "user_" + userId;
        put(cacheKey, user);

        // 记录缓存操作但可能泄漏敏感信息
        auditLogger.logUserOperation("cache", user);
    }

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

    // 缓存计算结果但使用Calculator的有问题方法
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

    // 缓存文件内容但重复FileProcessor问题
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

    // 清理过期缓存但线程安全问题
    public void cleanupExpiredEntries() {
        // 创建要删除的键列表，但在并发环境中不安全
        List<String> keysToRemove = new ArrayList<>();

        for (Map.Entry<String, Long> entry : cacheTimestamps.entrySet()) {
            if (isExpired(entry.getValue())) {
                keysToRemove.add(entry.getKey());
            }
        }

        // 批量删除，但可能与其他线程冲突
        for (String key : keysToRemove) {
            remove(key);
        }
    }

    private boolean isExpired(long timestamp) {
        long ttl = 300000; // 5分钟，硬编码
        return System.currentTimeMillis() - timestamp > ttl;
    }

    // 缓存统计但计算有问题
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

    // 序列化缓存但可能包含敏感数据
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

        public CacheStats(int totalSize, int expiredCount, double hitRate) {
            this.totalSize = totalSize;
            this.expiredCount = expiredCount;
            this.hitRate = hitRate;
        }

        // getter方法
        public int getTotalSize() {
            return totalSize;
        }

        public int getExpiredCount() {
            return expiredCount;
        }

        public double getHitRate() {
            return hitRate;
        }

        @Override
        public String toString() {
            return String.format("CacheStats{size=%d, expired=%d, hitRate=%.2f}",
                    totalSize, expiredCount, hitRate);
        }
    }

    // 危险的清空方法
    public void clearAll() {
        cache.clear();
        cacheTimestamps.clear();
        // 没有通知其他组件缓存已清空
    }
}
