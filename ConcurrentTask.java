import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 并发任务处理类 - 包含线程安全和并发问题
 */
public class ConcurrentTask {

    private static int counter = 0; // 线程不安全的计数器
    private List<String> results = new ArrayList<>(); // 非线程安全集合
    private Map<String, Object> cache = new HashMap<>(); // 非线程安全缓存

    // 竞态条件
    public void incrementCounter() {
        counter++; // 非原子操作
    }

    public int getCounter() {
        return counter;
    }

    // 双重检查锁定的错误实现
    private static volatile ConcurrentTask instance;

    public static ConcurrentTask getInstance() {
        if (instance == null) {
            synchronized (ConcurrentTask.class) {
                if (instance == null) {
                    instance = new ConcurrentTask(); // 正确，但有其他问题
                }
            }
        }
        return instance;
    }

    // 死锁风险
    private final Object lock1 = new Object();
    private final Object lock2 = new Object();

    public void method1() {
        synchronized (lock1) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            synchronized (lock2) {
                // 一些操作
            }
        }
    }

    public void method2() {
        synchronized (lock2) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            synchronized (lock1) {
                // 一些操作
            }
        }
    }

    // 不正确的线程池使用
    public void processItems(List<String> items) {
        ExecutorService executor = Executors.newFixedThreadPool(10);

        for (String item : items) {
            executor.submit(() -> {
                processItem(item);
                results.add("Processed: " + item); // 非线程安全操作
            });
        }

        // 没有shutdown和awaitTermination
    }

    private void processItem(String item) {
        // 模拟处理
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            // 不正确的中断处理
        }
    }

    // 不安全的缓存操作
    public Object getCachedValue(String key) {
        if (!cache.containsKey(key)) {
            // 计算值的过程可能很耗时
            Object value = computeExpensiveValue(key);
            cache.put(key, value); // 竞态条件
            return value;
        }
        return cache.get(key);
    }

    private Object computeExpensiveValue(String key) {
        try {
            Thread.sleep(2000); // 模拟耗时操作
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return "Value for " + key;
    }

    // 生产者消费者问题
    private Queue<String> queue = new LinkedList<>();
    private boolean finished = false;

    public void producer() {
        for (int i = 0; i < 100; i++) {
            queue.offer("Item " + i); // 非线程安全
        }
        finished = true; // 可见性问题
    }

    public void consumer() {
        while (!finished || !queue.isEmpty()) {
            String item = queue.poll(); // 可能NPE
            if (item != null) {
                System.out.println("Consumed: " + item);
            }
        }
    }

    // 资源竞争
    private int sharedResource = 0;

    public void updateResource(int value) {
        // 非原子操作
        sharedResource = sharedResource + value;
    }

    public int getResource() {
        return sharedResource;
    }

    // 不正确的同步
    public synchronized void synchronizedMethod() {
        // 在同步方法中调用其他对象的方法
        String result = externalService.process("data");
        results.add(result); // 外部调用可能耗时很长
    }

    private ExternalService externalService = new ExternalService();

    class ExternalService {
        public String process(String data) {
            try {
                Thread.sleep(5000); // 模拟网络调用
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return "Processed: " + data;
        }
    }

    // ThreadLocal内存泄漏
    private static ThreadLocal<StringBuilder> threadLocalBuilder = new ThreadLocal<StringBuilder>() {
        @Override
        protected StringBuilder initialValue() {
            return new StringBuilder();
        }
    };

    public String buildString(String... parts) {
        StringBuilder builder = threadLocalBuilder.get();
        for (String part : parts) {
            builder.append(part);
        }
        String result = builder.toString();
        // 没有清理ThreadLocal
        return result;
    }
}
