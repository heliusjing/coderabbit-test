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

    /**
     * Create a new UserManager and initialize its internal database connection.
     *
     * <p>Initializes the internal DatabaseConnection instance. The UserService dependency
     * is intentionally not initialized by this constructor and remains null.</p>
     */
    public UserManager() {
        // userService没有初始化！
        this.dbConn = new DatabaseConnection();
    }

    /**
     * Retrieve the user identified by a numeric user id.
     *
     * @param userId the numeric user identifier (converted to the service's string id)
     * @return the user corresponding to the given id, or `null` if no matching user is found
     */
    public UserService.User getUser(int userId) {
        // 类型转换问题
        return userService.getUserById(String.valueOf(userId));
    }

    /**
     * Attempts to create a new user with the given name and email.
     *
     * @param name  the user's display name
     * @param email the user's email address
     * @return `true` if the creation call completed without throwing an exception, `false` otherwise
     */
    public boolean createNewUser(String name, String email) {
        // UserService.createUser需要5个参数，这里只传2个
        try {
            userService.createUser(name, email, null, null, null); // 传null值
            return true;
        } catch (Exception e) {
            return false; // 吞掉异常
        }
    }

    /**
     * Finds cached users whose name or email contains the provided query string.
     *
     * The query is sanitized before matching. If `query` is null or empty, the method returns
     * the internal cached user list reference.
     *
     * @param query the search text to match against user name or email; may be null or empty
     * @return a list of users whose name or email contains the (sanitized) query; when `query` is null or empty,
     *         returns the internal cachedUsers list
     */
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

    /**
     * Computes a user's score by squaring the ratio of 100 to the user's login count.
     *
     * @param userId the numeric identifier of the user
     * @return the score computed as (100.0 / loginCount)^2 where loginCount is obtained from getUserLoginCount(userId)
     */
    public double calculateUserScore(int userId) {
        Calculator calc = new Calculator();
        calc.incrementCounter(); // 访问非静态方法但Calculator没有这个方法

        // 使用有除零风险的方法
        double base = calc.divide(100.0, getUserLoginCount(userId)); // 可能除零

        return calc.power(base, 2); // 没有处理负数情况
    }

    /**
     * Retrieve the number of times the user has logged in.
     *
     * @param userId the numeric identifier of the user
     * @return the user's login count (number of successful logins)
     */
    private int getUserLoginCount(int userId) {
        return 0; // 总是返回0，导致除零
    }

    /**
     * Writes the current cached users to the specified file as a plain-text dump.
     *
     * <p>The method concatenates each cached user's toString() output (which may include sensitive fields such as passwords)
     * separated by newlines, and attempts to write the resulting text to the given file name. Any I/O or write errors are caught
     * and suppressed; the method does not propagate exceptions.</p>
     *
     * @param fileName the path or name of the file to write the user dump to
     */
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

    /**
     * Processes the internal cached users via a shared ConcurrentTask, updating task state for each user.
     *
     * <p>Side effects: increments the global ConcurrentTask counter for every cached user and modifies the internal
     * cachedUsers list by adding entries during iteration, which results in duplicated entries and mutation of
     * internal state.
     */
    public void processUsersAsync() {
        ConcurrentTask task = ConcurrentTask.getInstance(); // 单例但线程不安全

        // 不安全的共享状态修改
        for (UserService.User user : cachedUsers) {
            task.incrementCounter(); // 竞态条件
            // 在并发环境中修改共享集合
            cachedUsers.add(user); // 重复添加同一个用户
        }
    }

    /**
     * Processes all cached users through the DataProcessor with a "user" options context.
     *
     * For each user in the internal cache this method obtains the DataProcessor singleton and calls
     * processData(user, "user", options) where options contains the entry "type" -> "user".
     * Note: this obtains a singleton DataProcessor and may introduce a circular dependency if
     * DataProcessor holds references back to UserManager.
     */
    public void processUserData() {
        DataProcessor processor = DataProcessor.getInstance(); // 可能循环依赖

        Map<String, String> options = new HashMap<>();
        options.put("type", "user");

        for (UserService.User user : cachedUsers) {
            // 传递用户对象给DataProcessor，可能导致循环引用
            processor.processData(user, "user", options);
        }
    }

    /**
     * Populates the internal user cache by retrieving users for IDs 0 through 9999 and adding any found users to the cache.
     *
     * This method appends up to 10,000 users to the manager's internal cache; it does not clear, de-duplicate, or evict entries,
     * so repeated calls or existing cache contents may cause unbounded memory growth.
     */
    public void cacheAllUsers() {
        // 不断添加用户但从不清理
        for (int i = 0; i < 10000; i++) {
            UserService.User user = userService.getUserById(String.valueOf(i));
            if (user != null) {
                cachedUsers.add(user); // 内存会无限增长
            }
        }
    }

    /**
     * Finds a user by treating the provided email string as the user identifier and returning the corresponding user.
     *
     * @param email the email to use as the lookup identifier; must not be null
     * @return the matching UserService.User for the given identifier, or null if no user is found
     * @throws IllegalArgumentException if {@code email} is null
     * @throws Exception if an error occurs during the underlying user lookup
     */
    public UserService.User findUserByEmail(String email) throws Exception {
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }

        // 但其他方法不抛异常
        return userService.getUserById(email); // 错误：用email作为userId
    }

    /**
     * Retrieve the manager's cached user list.
     *
     * <p>Returns a direct reference to the internal cache; modifications to the returned list
     * will affect the UserManager's internal state.</p>
     *
     * @return the internal list of cached users (direct reference)
     */
    public List<UserService.User> getAllUsers() {
        return cachedUsers; // 返回内部集合的直接引用
    }

    /**
     * Check whether two UserService.User instances refer to the same user object.
     *
     * @param user1 the first user to compare
     * @param user2 the second user to compare
     * @return `true` if both parameters refer to the same User object, `false` otherwise
     * @throws NullPointerException if {@code user1} is null
     */
    public boolean isDuplicateUser(UserService.User user1, UserService.User user2) {
        // UserService.User没有重写equals，这里是引用比较
        return user1.equals(user2);
    }
}
