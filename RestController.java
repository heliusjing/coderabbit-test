import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.*;

/**
 * REST控制器类 - 包含Web安全、验证和API设计问题
 */
public class RestController {

    private static final String SECRET_KEY = "mySecretKey123"; // 硬编码密钥
    private Map<String, User> users = new HashMap<>();

    // 缺少输入验证和身份认证
    public String createUser(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        // 没有验证输入
        User user = new User(name, email, password);
        users.put(email, user);

        // 返回敏感信息
        return "User created: " + user.toString();
    }

    // SQL注入风险
    public String getUserData(HttpServletRequest request) {
        String userId = request.getParameter("id");
        // 直接拼接SQL，存在注入风险
        String sql = "SELECT * FROM users WHERE id = " + userId;
        return executeQuery(sql);
    }

    // 缺少CSRF保护
    public void deleteUser(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        // 没有CSRF token验证
        users.remove(userId);
    }

    // 信息泄漏
    public String login(HttpServletRequest request) {
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        User user = users.get(email);
        if (user == null) {
            return "User not found with email: " + email; // 泄漏用户是否存在
        }

        if (!user.password.equals(password)) {
            return "Invalid password for user: " + email; // 泄漏信息
        }

        return "Login successful. Secret key: " + SECRET_KEY; // 泄漏密钥
    }

    // 没有速率限制
    public String sendEmail(HttpServletRequest request) {
        String email = request.getParameter("email");
        String subject = request.getParameter("subject");
        String body = request.getParameter("body");

        // 没有验证发送频率
        for (int i = 0; i < 100; i++) {
            sendEmailInternal(email, subject, body);
        }

        return "Emails sent";
    }

    // 文件上传漏洞
    public String uploadFile(HttpServletRequest request) {
        String fileName = request.getParameter("fileName");
        String content = request.getParameter("content");

        // 没有验证文件类型和大小
        // 没有防止路径遍历
        String path = "/uploads/" + fileName;
        saveFile(path, content);

        return "File uploaded to: " + path;
    }

    // XSS漏洞
    public String displayUserComment(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String comment = request.getParameter("comment");

        // 直接输出用户输入，存在XSS风险
        response.getWriter().write("<div>User comment: " + comment + "</div>");
        return null;
    }

    // 权限绕过
    public String getAdminData(HttpServletRequest request) {
        String userRole = request.getParameter("role");

        // 客户端传递权限信息
        if ("admin".equals(userRole)) {
            return "Sensitive admin data: " + getSecretData();
        }

        return "Access denied";
    }

    // 不安全的重定向
    public void redirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("redirect");

        // 没有验证重定向URL
        response.sendRedirect(url);
    }

    // 会话固定漏洞
    public String createSession(HttpServletRequest request) {
        String sessionId = request.getParameter("sessionId");

        // 使用客户端提供的会话ID
        if (sessionId != null) {
            request.getSession().setAttribute("customSessionId", sessionId);
        }

        return "Session created with ID: " + sessionId;
    }

    // 不正确的错误处理
    public String processPayment(HttpServletRequest request) {
        try {
            String amount = request.getParameter("amount");
            String cardNumber = request.getParameter("cardNumber");

            // 模拟支付处理
            if (cardNumber.length() != 16) {
                throw new RuntimeException("Invalid card number: " + cardNumber);
            }

            return "Payment processed for amount: " + amount;

        } catch (Exception e) {
            // 返回详细错误信息
            return "Payment failed: " + e.getMessage() + " Stack trace: " + Arrays.toString(e.getStackTrace());
        }
    }

    // 资源消耗攻击
    public String generateReport(HttpServletRequest request) {
        String format = request.getParameter("format");
        int size = Integer.parseInt(request.getParameter("size"));

        // 没有限制资源使用
        List<String> data = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            data.add("Data item " + i);
        }

        return "Generated report with " + data.size() + " items";
    }

    // 不安全的API密钥处理
    public String callExternalAPI(HttpServletRequest request) {
        String apiKey = request.getParameter("apiKey");

        // API密钥通过URL参数传递
        String url = "https://api.example.com/data?key=" + apiKey;

        // 记录包含API密钥的URL
        System.out.println("Calling API: " + url);

        return "API call completed";
    }

    // 辅助方法
    private String executeQuery(String sql) {
        return "Query result for: " + sql;
    }

    private void sendEmailInternal(String email, String subject, String body) {
        // 模拟发送邮件
    }

    private void saveFile(String path, String content) {
        // 模拟保存文件
    }

    private String getSecretData() {
        return "TOP_SECRET_ADMIN_DATA";
    }

    // 用户类
    static class User {
        String name;
        String email;
        String password; // 明文存储密码

        User(String name, String email, String password) {
            this.name = name;
            this.email = email;
            this.password = password;
        }

        @Override
        public String toString() {
            return "User{name='" + name + "', email='" + email + "', password='" + password + "'}";
        }
    }
}
