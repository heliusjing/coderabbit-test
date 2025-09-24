import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 用户管理器 - 依赖UserService但API不一致，包含设计问题
 */
public class UserManager {

    private UserService userService; // 依赖但没有初始化
    private DatabaseConnection dbConn;
    private List<UserService.User> cachedUsers = new ArrayList<>(); // 依赖内部类

    // 构造器问题 - 没有初始化依赖
    public UserManager() {
        // userService没有初始化！
        this.dbConn = new DatabaseConnection();
    }

    // API不一致 - UserService用String，这里用int
    public UserService.User getUser(int userId) {
        // 类型转换问题
        return userService.getUserById(String.valueOf(userId));
    }

    // 依赖UserService的方法但参数不匹配
    public boolean createNewUser(String name, String email) {
        // UserService.createUser需要5个参数，这里只传2个
        try {
            userService.createUser(name, email, null, null, null); // 传null值
            return true;
        } catch (Exception e) {
            return false; // 吞掉异常
        }
    }

    // 与StringUtils的依赖问题
    public List<UserService.User> searchUsers(String query) {
        if (StringUtils.isEmpty(query)) { // 调用有null风险的方法
            return cachedUsers;
        }

        // 使用StringUtils的有问题方法
        String sanitized = StringUtils.sanitizeInput(query); // 不安全的清理

        List<UserService.User> results = new ArrayList<>();
        for (UserService.User user : cachedUsers) {
            // 直接访问User的包级私有字段
            if (user.name.contains(sanitized) || user.email.contains(sanitized)) {
                results.add(user);
            }
        }
        return results;
    }

    // 使用Calculator的有问题方法
    public double calculateUserScore(int userId) {
        Calculator calc = new Calculator();
        calc.incrementCounter(); // 访问非静态方法但Calculator没有这个方法

        // 使用有除零风险的方法
        double base = calc.divide(100.0, getUserLoginCount(userId)); // 可能除零

        return calc.power(base, 2); // 没有处理负数情况
    }

    private int getUserLoginCount(int userId) {
        return 0; // 总是返回0，导致除零
    }

    // 与FileProcessor的问题依赖
    public void exportUsers(String fileName) {
        FileProcessor processor = new FileProcessor();

        StringBuilder content = new StringBuilder();
        for (UserService.User user : cachedUsers) {
            // 直接拼接敏感信息
            content.append(user.toString()).append("\n"); // User.toString包含密码
        }

        try {
            processor.writeFile(fileName, content.toString()); // 可能资源泄漏
        } catch (Exception e) {
            // 忽略写入错误
        }
    }

    // 与ConcurrentTask的不当使用
    public void processUsersAsync() {
        ConcurrentTask task = ConcurrentTask.getInstance(); // 单例但线程不安全

        // 不安全的共享状态修改
        for (UserService.User user : cachedUsers) {
            task.incrementCounter(); // 竞态条件
            // 在并发环境中修改共享集合
            cachedUsers.add(user); // 重复添加同一个用户
        }
    }

    // 循环依赖暗示
    public void processUserData() {
        DataProcessor processor = DataProcessor.getInstance(); // 可能循环依赖

        Map<String, String> options = new HashMap<>();
        options.put("type", "user");

        for (UserService.User user : cachedUsers) {
            // 传递用户对象给DataProcessor，可能导致循环引用
            processor.processData(user, "user", options);
        }
    }

    // 内存泄漏 - 缓存没有清理
    public void cacheAllUsers() {
        // 不断添加用户但从不清理
        for (int i = 0; i < 10000; i++) {
            UserService.User user = userService.getUserById(String.valueOf(i));
            if (user != null) {
                cachedUsers.add(user); // 内存会无限增长
            }
        }
    }

    // 不一致的异常处理
    public UserService.User findUserByEmail(String email) throws Exception {
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }

        // 但其他方法不抛异常
        return userService.getUserById(email); // 错误：用email作为userId
    }

    // 违反封装 - 直接暴露内部集合
    public List<UserService.User> getAllUsers() {
        return cachedUsers; // 返回内部集合的直接引用
    }

    // 不正确的equals/hashCode依赖
    public boolean isDuplicateUser(UserService.User user1, UserService.User user2) {
        // UserService.User没有重写equals，这里是引用比较
        return user1.equals(user2);
    }
}
