import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 用户服务类 - 故意包含多个安全和代码质量问题
 * 
 * @author chengfei.jin
 */
public class UserService {
    private static Connection connection;
    private String adminPassword = "admin123"; // 硬编码密码

    // SQL注入漏洞
    public User getUserById(String userId) {
        try {
            String sql = "SELECT * FROM users WHERE id = " + userId; // SQL注入风险
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(sql);

            if (rs.next()) {
                return new User(rs.getString("name"), rs.getString("email"));
            }
        } catch (Exception e) {
            // 空的异常处理
        }
        return null;
    }

    // 密码处理问题
    public boolean validatePassword(String username, String password) {
        String storedPassword = getPasswordFromDB(username);
        // 直接比较明文密码
        if (password.equals(storedPassword)) {
            return true;
        }
        return false;
    }

    // 方法太长，职责不单一
    public void createUser(String name, String email, String password, String address, String phone) {
        if (name == null || email == null)
            return; // 缺少详细验证

        // 未加密存储密码
        String sql = "INSERT INTO users (name, email, password, address, phone) VALUES ('"
                + name + "', '" + email + "', '" + password + "', '" + address + "', '" + phone + "')";

        try {
            Statement stmt = connection.createStatement();
            stmt.executeUpdate(sql);

            // 发送欢迎邮件
            sendWelcomeEmail(email);

            // 记录日志
            System.out.println("User created: " + name);

            // 创建默认设置
            createDefaultSettings(name);

        } catch (SQLException e) {
            e.printStackTrace(); // 不应该直接打印栈跟踪
        }
    }

    private String getPasswordFromDB(String username) {
        // 模拟返回明文密码
        return "password123";
    }

    private void sendWelcomeEmail(String email) {
        // 空实现
    }

    private void createDefaultSettings(String username) {
        // 空实现
    }

    // 内部类没有访问修饰符
    class User {
        String name;
        String email;

        User(String name, String email) {
            this.name = name;
            this.email = email;
        }
    }
}
