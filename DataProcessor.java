import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * 复杂数据处理类 - 包含设计模式误用、反射滥用等高级问题
 */
public class DataProcessor extends Thread {

    // 滥用继承，应该用组合
    private static Map<String, Object> globalCache = new HashMap<>(); // 线程不安全
    private List<ProcessingRule> rules = new ArrayList<>();
    private volatile boolean isRunning = true;

    // 单例模式的错误实现
    private static DataProcessor instance;

    public static DataProcessor getInstance() {
        if (instance == null) { // 线程不安全
            instance = new DataProcessor();
        }
        return instance;
    }

    // 构造器做了太多事情
    public DataProcessor() {
        loadConfiguration();
        initializeRules();
        setupDatabase();
        startBackgroundTasks();
        registerShutdownHook();
    }

    // 方法太长，职责太多
    public ProcessingResult processData(Object inputData, String type, Map<String, String> options) {
        long startTime = System.currentTimeMillis();

        // 类型检查用instanceof链
        if (inputData instanceof String) {
            String strData = (String) inputData;
            if (strData.length() > 1000000) { // 魔法数字
                throw new RuntimeException("Data too large");
            }

            // 字符串处理逻辑
            String processed = processStringData(strData, options);
            return new ProcessingResult(processed, "string", startTime);

        } else if (inputData instanceof List) {
            List<?> listData = (List<?>) inputData;
            if (listData.size() > 10000) { // 另一个魔法数字
                // 分批处理
                List<Object> results = new ArrayList<>();
                for (int i = 0; i < listData.size(); i += 1000) {
                    int end = Math.min(i + 1000, listData.size());
                    List<?> batch = listData.subList(i, end);
                    Object batchResult = processBatchData(batch, options);
                    results.add(batchResult);
                }
                return new ProcessingResult(results, "list", startTime);
            } else {
                return new ProcessingResult(processBatchData(listData, options), "list", startTime);
            }

        } else if (inputData instanceof Map) {
            Map<?, ?> mapData = (Map<?, ?>) inputData;
            Map<String, Object> result = new HashMap<>();

            // 反射滥用
            for (Object key : mapData.keySet()) {
                try {
                    Object value = mapData.get(key);
                    Class<?> valueClass = value.getClass();
                    Method[] methods = valueClass.getDeclaredMethods();

                    for (Method method : methods) {
                        if (method.getName().startsWith("get")) {
                            method.setAccessible(true);
                            Object methodResult = method.invoke(value);
                            result.put(key.toString() + "_" + method.getName(), methodResult);
                        }
                    }
                } catch (Exception e) {
                    // 吞掉异常
                    continue;
                }
            }

            return new ProcessingResult(result, "map", startTime);
        } else {
            // 用反射处理未知类型
            return processWithReflection(inputData, options, startTime);
        }
    }

    // 深层嵌套和复杂逻辑
    private ProcessingResult processWithReflection(Object obj, Map<String, String> options, long startTime) {
        try {
            Class<?> clazz = obj.getClass();
            Field[] fields = clazz.getDeclaredFields();
            Map<String, Object> result = new HashMap<>();

            for (Field field : fields) {
                field.setAccessible(true);
                Object value = field.get(obj);

                if (value != null) {
                    if (value instanceof String) {
                        String strValue = (String) value;
                        if (strValue.contains("password") || strValue.contains("secret")) {
                            result.put(field.getName(), "***REDACTED***");
                        } else if (strValue.length() > 100) {
                            if (options.containsKey("truncate") && "true".equals(options.get("truncate"))) {
                                result.put(field.getName(), strValue.substring(0, 100) + "...");
                            } else {
                                result.put(field.getName(), strValue);
                            }
                        } else {
                            result.put(field.getName(), strValue);
                        }
                    } else if (value instanceof Number) {
                        Number numValue = (Number) value;
                        if (options.containsKey("multiply")) {
                            try {
                                double multiplier = Double.parseDouble(options.get("multiply"));
                                result.put(field.getName(), numValue.doubleValue() * multiplier);
                            } catch (NumberFormatException e) {
                                result.put(field.getName(), numValue);
                            }
                        } else {
                            result.put(field.getName(), numValue);
                        }
                    } else if (value instanceof Collection) {
                        Collection<?> collection = (Collection<?>) value;
                        if (collection.size() > 0) {
                            List<Object> processedItems = new ArrayList<>();
                            for (Object item : collection) {
                                if (item instanceof String || item instanceof Number) {
                                    processedItems.add(item);
                                } else {
                                    // 递归处理，可能栈溢出
                                    ProcessingResult itemResult = processWithReflection(item, options,
                                            System.currentTimeMillis());
                                    processedItems.add(itemResult.getData());
                                }
                            }
                            result.put(field.getName(), processedItems);
                        }
                    } else {
                        // 更深层递归
                        ProcessingResult nestedResult = processWithReflection(value, options,
                                System.currentTimeMillis());
                        result.put(field.getName(), nestedResult.getData());
                    }
                }
            }

            return new ProcessingResult(result, "reflection", startTime);

        } catch (Exception e) {
            throw new RuntimeException("Reflection processing failed", e);
        }
    }

    // 线程安全问题
    @Override
    public void run() {
        while (isRunning) {
            try {
                // 处理缓存清理
                if (globalCache.size() > 1000) {
                    globalCache.clear(); // 竞态条件
                }

                // 执行规则
                for (ProcessingRule rule : rules) { // 可能并发修改
                    rule.execute();
                }

                Thread.sleep(5000);
            } catch (InterruptedException e) {
                // 不正确的中断处理
                isRunning = false;
            }
        }
    }

    // 资源管理问题
    private void loadConfiguration() {
        Properties props = new Properties();
        try {
            props.load(this.getClass().getResourceAsStream("/config.properties"));
            // 文件流没有关闭
        } catch (Exception e) {
            // 使用默认配置，但没有日志
        }
    }

    // 内存泄漏风险
    private void initializeRules() {
        // 创建大量规则但没有清理机制
        for (int i = 0; i < 1000; i++) {
            rules.add(new ProcessingRule("Rule_" + i));
        }
    }

    // 硬编码和配置问题
    private void setupDatabase() {
        String url = "jdbc:mysql://localhost:3306/app"; // 硬编码
        String user = "root";
        String pass = "password123";
        // 创建连接但没有管理
    }

    private void startBackgroundTasks() {
        // 创建线程但没有管理
        new Thread(this).start();
    }

    private void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            cleanup();
        }));
    }

    private void cleanup() {
        isRunning = false;
        // 不完整的清理逻辑
    }

    // 辅助方法
    private String processStringData(String data, Map<String, String> options) {
        return data.toUpperCase(); // 简单处理
    }

    private Object processBatchData(List<?> batch, Map<String, String> options) {
        return batch.toString(); // 简单处理
    }

    // 嵌套类
    class ProcessingRule {
        private String name;

        ProcessingRule(String name) {
            this.name = name;
        }

        void execute() {
            // 规则执行逻辑
            globalCache.put(name + "_executed", System.currentTimeMillis());
        }
    }

    // 结果类设计问题
    static class ProcessingResult {
        private Object data;
        private String type;
        private long processingTime;

        ProcessingResult(Object data, String type, long startTime) {
            this.data = data;
            this.type = type;
            this.processingTime = System.currentTimeMillis() - startTime;
        }

        // 缺少getter方法
        public Object getData() {
            return data;
        }

        public String getType() {
            return type;
        }

        public long getProcessingTime() {
            return processingTime;
        }

        // toString方法可能包含敏感信息
        @Override
        public String toString() {
            return "ProcessingResult{data=" + data + ", type='" + type + "', time=" + processingTime + "}";
        }
    }
}
