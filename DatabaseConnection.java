import java.io.FileInputStream;
import java.io.IOException;
import java.sql.*;
import java.util.Properties;

/**
 * 数据库连接管理类 - 包含资源泄漏和连接管理问题
 */
public class DatabaseConnection {
    private static String DB_URL = "jdbc:mysql://localhost:3306/test"; // 硬编码URL
    private static String USERNAME = "root";
    private static String PASSWORD = "123456"; // 硬编码密码

    // 未使用连接池
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, USERNAME, PASSWORD);
    }

    // 资源泄漏 - 没有关闭连接
    public void executeQuery(String sql) {
        try {
            Connection conn = getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);

            while (rs.next()) {
                System.out.println(rs.getString(1));
            }
            // 没有关闭资源！
        } catch (SQLException e) {
            System.out.println("Database error occurred");
        }
    }

    // 不正确的事务处理
    public void updateUserData(int userId, String newName) {
        Connection conn = null;
        try {
            conn = getConnection();
            conn.setAutoCommit(false);

            PreparedStatement stmt1 = conn.prepareStatement("UPDATE users SET name = ? WHERE id = ?");
            stmt1.setString(1, newName);
            stmt1.setInt(2, userId);
            stmt1.executeUpdate();

            // 这里可能抛出异常
            PreparedStatement stmt2 = conn
                    .prepareStatement("UPDATE user_stats SET last_updated = NOW() WHERE user_id = ?");
            stmt2.setInt(1, userId);
            stmt2.executeUpdate();

            conn.commit(); // 如果上面出错，这行不会执行

        } catch (SQLException e) {
            // 没有回滚事务
            e.printStackTrace();
        } finally {
            // 不正确的资源清理
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // 忽略关闭异常
                }
            }
        }
    }

    // 批量操作效率低下
    public void insertMultipleUsers(String[][] userData) {
        for (String[] user : userData) {
            // 每次循环都创建新连接
            try (Connection conn = getConnection()) {
                String sql = "INSERT INTO users (name, email) VALUES (?, ?)";
                PreparedStatement stmt = conn.prepareStatement(sql);
                stmt.setString(1, user[0]);
                stmt.setString(2, user[1]);
                stmt.executeUpdate();
            } catch (SQLException e) {
                continue; // 忽略错误继续处理
            }
        }
    }

    // 同步方法可能导致性能问题
    public synchronized ResultSet queryUsers() throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users");
        // 返回ResultSet但连接可能被关闭
    }

    // 配置文件处理有问题
    public void loadDatabaseConfig() {
        Properties props = new Properties();
        try {
            FileInputStream fis = new FileInputStream("db.properties");
            props.load(fis);
            // 没有关闭FileInputStream

            DB_URL = props.getProperty("db.url");
            USERNAME = props.getProperty("db.username");
            PASSWORD = props.getProperty("db.password");

        } catch (IOException e) {
            // 使用默认配置，但没有日志记录
        }
    }
}
