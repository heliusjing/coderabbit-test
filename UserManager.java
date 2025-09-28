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
     * Initializes a UserManager instance by creating its DatabaseConnection while leaving service dependencies unset.
     *
     * <p>This constructor instantiates the internal {@code dbConn}. The {@code userService} dependency is not initialized
     * by this constructor and will remain {@code null} until set by callers; callers must provide or inject a valid
     * UserService before invoking methods that depend on it.</p>
     */
    public UserManager() {
        // userService没有初始化！
        this.dbConn = new DatabaseConnection();
    }

    /**
     * Retrieves a user for the given numeric id.
     *
     * @param userId the numeric user identifier
     * @return the matching UserService.User, or `null` if no user is found
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
     * @return `true` if the user was created successfully, `false` if an exception occurred during creation
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
     * Searches the internal user cache for entries whose name or email contains the provided query.
     *
     * @param query the search string; if null or empty, the internal cached user list is returned
     * @return the internal cached user list when {@code query} is null or empty; otherwise a new list containing users whose name or email contains the sanitized query (case-sensitive)
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
     * Computes a user's score based on their login count.
     *
     * @returns the computed score as a double; may be Infinity or NaN if the underlying login count is zero or otherwise produces an invalid divisor/result.
     */
    public double calculateUserScore(int userId) {
        Calculator calc = new Calculator();
        calc.incrementCounter(); // 访问非静态方法但Calculator没有这个方法

        // 使用有除零风险的方法
        double base = calc.divide(100.0, getUserLoginCount(userId)); // 可能除零

        return calc.power(base, 2); // 没有处理负数情况
    }

    /**
     * Retrieve the recorded login count for a user.
     *
     * @return the user's login count; this implementation currently always returns 0
     */
    private int getUserLoginCount(int userId) {
        return 0; // 总是返回0，导致除零
    }

    /**
     * Exports the cached users to the specified file, writing each user's string representation on its own line.
     *
     * <p>Note: this method writes the result of User.toString() (which may include sensitive fields such as passwords)
     * and ignores any I/O errors that occur during writing.</p>
     *
     * @param fileName the path of the file to write the exported user data to
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
     * Processes the internal cached users by interacting with a shared ConcurrentTask and mutating the cache.
     *
     * <p>For each user in {@code cachedUsers} this method increments a counter on a singleton {@code ConcurrentTask}
     * and adds the same user back into {@code cachedUsers}, thereby mutating the internal cache.</p>
     *
     * <p>Side effects: increments a shared task counter and appends users to the internal {@code cachedUsers} list.
     * This method is not thread-safe; concurrent use may cause race conditions, duplicate entries, and
     * {@link java.util.ConcurrentModificationException} or other undefined behavior.</p>
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
     * Processes every user in the internal cache by sending each user to the data processor with a "user" type option.
     *
     * <p>For each cached user this method invokes the data processor with the user object, the literal type string "user", and an options map containing "type"="user". The method performs processing for side effects and does not return a value.</p>
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
     * Populates the internal cache by fetching users for ids 0 through 9999 and appending any non-null results.
     *
     * This method converts each index in the range [0, 9999] to a string, calls the user service to retrieve a user,
     * and adds non-null users to the internal cachedUsers list without clearing or deduplicating existing entries.
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
     * Finds and returns the user corresponding to the given email string.
     *
     * @param email the email to look up; must not be null
     * @return the UserService.User matching the provided email
     * @throws IllegalArgumentException if {@code email} is null
     * @throws Exception if the underlying user service fails to retrieve the user
     */
    public UserService.User findUserByEmail(String email) throws Exception {
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }

        // 但其他方法不抛异常
        return userService.getUserById(email); // 错误：用email作为userId
    }

    /**
     * Provide direct access to the manager's internal cached list of users.
     *
     * @return the internal mutable list of cached users; modifications to the returned list will affect the manager's cache
     */
    public List<UserService.User> getAllUsers() {
        return cachedUsers; // 返回内部集合的直接引用
    }

    /**
     * Determines whether two UserService.User references refer to the same object instance.
     *
     * This performs reference (identity) comparison and does not compare user fields for logical equality.
     *
     * @param user1 the first user reference to compare
     * @param user2 the second user reference to compare
     * @return `true` if both references refer to the same object, `false` otherwise
     */
    public boolean isDuplicateUser(UserService.User user1, UserService.User user2) {
        // UserService.User没有重写equals，这里是引用比较
        return user1.equals(user2);
    }
}
