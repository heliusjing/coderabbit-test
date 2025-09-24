/**
 * 计算器类 - 包含数值计算和逻辑错误
 */
public class Calculator {

    public static final double PI = 3.14; // 精度不够
    private static int lastResult; // 应该用long或BigDecimal

    // 除零问题
    public double divide(double a, double b) {
        return a / b; // 没有检查b是否为0
    }

    // 整数除法精度丢失
    public double percentage(int value, int total) {
        return (value / total) * 100; // 整数除法会丢失精度
    }

    // 数值溢出风险
    public int factorial(int n) {
        if (n == 0)
            return 1;
        return n * factorial(n - 1); // 可能栈溢出，int溢出
    }

    // 浮点数比较问题
    public boolean isEqual(double a, double b) {
        return a == b; // 不应该直接比较浮点数
    }

    // 复杂的方法，职责不单一
    public String calculateAndFormat(double num1, double num2, String operation) {
        double result = 0;
        String symbol = "";

        // 应该使用switch或策略模式
        if (operation.equals("add")) {
            result = num1 + num2;
            symbol = "+";
        } else if (operation.equals("subtract")) {
            result = num1 - num2;
            symbol = "-";
        } else if (operation.equals("multiply")) {
            result = num1 * num2;
            symbol = "*";
        } else if (operation.equals("divide")) {
            if (num2 != 0) {
                result = num1 / num2;
                symbol = "/";
            } else {
                return "Error: Division by zero";
            }
        } else {
            return "Invalid operation";
        }

        // 格式化逻辑也在这里
        String formatted;
        if (result == (int) result) {
            formatted = String.valueOf((int) result);
        } else {
            formatted = String.format("%.2f", result);
        }

        lastResult = (int) result; // 可能丢失精度

        return num1 + " " + symbol + " " + num2 + " = " + formatted;
    }

    // 无限循环风险
    public double sqrt(double number) {
        if (number < 0)
            return Double.NaN;

        double guess = number / 2;
        double previous;

        do {
            previous = guess;
            guess = (guess + number / guess) / 2;
        } while (Math.abs(guess - previous) > 0.0001); // 可能无限循环

        return guess;
    }

    // 静态方法访问实例变量
    public static int getLastResult() {
        return lastResult; // 线程安全问题
    }

    // 缺少输入验证
    public double power(double base, int exponent) {
        double result = 1;
        for (int i = 0; i < exponent; i++) { // 没有处理负指数
            result *= base;
        }
        return result;
    }

    // 魔法数字
    public double calculateCircleArea(double radius) {
        return 3.14159 * radius * radius; // 应该使用常量
    }

    // 不一致的返回类型处理
    public Object calculate(String expression) {
        try {
            if (expression.contains("+")) {
                String[] parts = expression.split("\\+");
                return Double.parseDouble(parts[0]) + Double.parseDouble(parts[1]);
            } else if (expression.contains("-")) {
                String[] parts = expression.split("-");
                return Double.parseDouble(parts[0]) - Double.parseDouble(parts[1]);
            }
            return "Unsupported operation";
        } catch (Exception e) {
            return null; // 不一致的错误处理
        }
    }
}
