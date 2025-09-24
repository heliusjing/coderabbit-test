import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 字符串工具类 - 包含空指针、性能和逻辑问题
 */
public class StringUtils {

    private static final String SPECIAL_CHARS = "!@#$%^&*()";

    // 空指针风险
    public static boolean isEmpty(String str) {
        return str.length() == 0; // 没有检查null
    }

    // 性能问题 - 字符串拼接
    public static String joinStrings(String[] strings, String separator) {
        String result = "";
        for (int i = 0; i < strings.length; i++) {
            result += strings[i]; // 不应该用+拼接
            if (i < strings.length - 1) {
                result += separator;
            }
        }
        return result;
    }

    // 正则表达式每次都编译
    public static boolean isValidEmail(String email) {
        if (email == null)
            return false;
        return email.matches("^[A-Za-z0-9+_.-]+@(.+)$"); // 简单的正则，每次都编译
    }

    // 不正确的字符串比较
    public static boolean isCommand(String input, String command) {
        return input.toLowerCase() == command.toLowerCase(); // 应该用equals
    }

    // 无限循环风险
    public static String removeAllSpaces(String str) {
        while (str.contains(" ")) {
            str = str.replace(" ", ""); // 可能无限循环
        }
        return str;
    }

    // 内存泄漏风险
    public static List<String> splitAndCache(String text, String delimiter) {
        // 静态缓存但没有清理机制
        static Map<String, List<String>> cache = new HashMap<>();

        if (cache.containsKey(text)) {
            return cache.get(text);
        }

        List<String> result = Arrays.asList(text.split(delimiter));
        cache.put(text, result); // 缓存会无限增长
        return result;
    }

    // 不安全的字符串操作
    public static String sanitizeInput(String input) {
        if (input == null)
            return null;

        // 不完整的清理
        return input.replace("<script>", "")
                .replace("</script>", "")
                .replace("javascript:", "");
        // 容易被绕过
    }

    // 硬编码和魔法数字
    public static String truncate(String str, int maxLength) {
        if (str.length() > maxLength) {
            return str.substring(0, maxLength) + "..."; // 魔法字符串
        }
        return str;
    }

    // 效率低下的字符计数
    public static int countOccurrences(String text, char target) {
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == target) {
                count++;
            }
        }
        return count; // 可以用Collections.frequency或Stream
    }

    // 不正确的编码处理
    public static String encodeString(String input) {
        try {
            return java.net.URLEncoder.encode(input, "UTF-8");
        } catch (Exception e) {
            return input; // 忽略编码异常
        }
    }

    // 复杂的条件判断
    public static boolean isValidPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (c >= 'A' && c <= 'Z')
                hasUpper = true;
            if (c >= 'a' && c <= 'z')
                hasLower = true;
            if (c >= '0' && c <= '9')
                hasDigit = true;
            if (SPECIAL_CHARS.indexOf(c) != -1)
                hasSpecial = true;
        }

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    // 线程安全问题
    private static StringBuilder buffer = new StringBuilder(); // 共享可变状态

    public static String processText(String input) {
        buffer.setLength(0); // 清空但线程不安全
        buffer.append("Processed: ");
        buffer.append(input);
        return buffer.toString();
    }

    // 递归可能栈溢出
    public static String reverse(String str) {
        if (str.length() <= 1) {
            return str;
        }
        return reverse(str.substring(1)) + str.charAt(0);
    }

    // 不一致的null处理
    public static String capitalize(String str) {
        if (str == null || str.isEmpty()) {
            return str; // 对null和empty不一致处理
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
    }
}
