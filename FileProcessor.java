import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * 文件处理类 - 包含IO异常处理和资源管理问题
 */
public class FileProcessor {

    private static final String DEFAULT_ENCODING = "UTF-8";
    private List<String> processedFiles = new ArrayList<>();

    // 不正确的异常处理
    public String readFile(String fileName) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            StringBuilder content = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            // 没有关闭reader！
            return content.toString();

        } catch (Exception e) {
            return ""; // 吞掉所有异常
        }
    }

    // 资源泄漏
    public void writeFile(String fileName, String content) throws IOException {
        FileWriter writer = new FileWriter(fileName);
        writer.write(content);
        // 没有关闭writer或处理异常
    }

    // 大文件内存问题
    public List<String> readAllLines(String fileName) {
        List<String> lines = new ArrayList<>();
        try {
            // 一次性读取所有行到内存
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            reader.close();
        } catch (IOException e) {
            System.out.println("Error reading file: " + fileName);
        }
        return lines;
    }

    // 不安全的文件路径操作
    public void copyFile(String sourcePath, String destPath) {
        try {
            // 没有验证路径安全性
            File source = new File(sourcePath);
            File dest = new File(destPath);

            FileInputStream fis = new FileInputStream(source);
            FileOutputStream fos = new FileOutputStream(dest);

            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) > 0) {
                fos.write(buffer, 0, length);
            }

            // 只关闭了一个流
            fis.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 同步方法性能问题
    public synchronized void processFile(String fileName) {
        if (processedFiles.contains(fileName)) {
            return;
        }

        try {
            Thread.sleep(1000); // 模拟长时间处理
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        processedFiles.add(fileName);
    }

    // 递归删除目录 - 安全风险
    public void deleteDirectory(File directory) {
        if (directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    deleteDirectory(file); // 可能栈溢出
                }
            }
        }
        directory.delete(); // 没有检查删除结果
    }

    // 硬编码文件路径
    public void createLogFile() {
        try {
            File logFile = new File("/tmp/app.log"); // 硬编码路径
            if (!logFile.exists()) {
                logFile.createNewFile();
            }

            FileWriter writer = new FileWriter(logFile, true);
            writer.write("Log entry at " + new Date());
            writer.close();

        } catch (IOException e) {
            // 忽略异常
        }
    }

    // 不正确的文件检查
    public boolean isValidFile(String fileName) {
        File file = new File(fileName);
        return file.exists(); // 没有检查是否为文件、是否可读等
    }

    // CSV解析问题
    public List<String[]> parseCsv(String fileName) {
        List<String[]> records = new ArrayList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            String line;
            while ((line = reader.readLine()) != null) {
                // 简单分割，没有处理引号内的逗号
                String[] fields = line.split(",");
                records.add(fields);
            }
        } catch (IOException e) {
            return null; // 不一致的返回值
        }
        return records;
    }

    // 临时文件没有清理
    public String processLargeFile(String inputFile) {
        try {
            File tempFile = File.createTempFile("processing", ".tmp");
            // 处理逻辑...
            return tempFile.getAbsolutePath();
            // 没有清理临时文件！
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
