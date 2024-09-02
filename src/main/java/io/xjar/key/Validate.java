package io.xjar.key;

import io.xjar.AESUtil;
import io.xjar.XConstants;
import io.xjar.XKit;
import io.xjar.XLauncher;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;

public class Validate {

    // 设置是否启动器参数
    public String validate() {
        try {
            byte[] text = getConfigContent();
            return decrypt(new String(text));
        } catch (Exception e) {
            System.out.println("解密参数不存在,无法启动");
            System.exit(1);
        }
        return null;
    }

    public byte[] getConfigContent() throws IOException {
        List<String> iniList = Arrays.asList("config.ini", "config/config.ini");
        File projectPath = null;
        for (String iniPath : iniList) {
            projectPath = new File(System.getProperty("user.dir") + File.separator + iniPath);
            if (projectPath.exists()) {
                Path path = projectPath.toPath();
                return Files.readAllBytes(path);
            }
        }
        // 添加一个直接读取application配置文件的功能
        List<String> ymlList = Arrays.asList("application.yml","config/application.yml");
        for (String ymlPath : ymlList) {
            projectPath = new File(System.getProperty("user.dir") + File.separator + ymlPath);
            if(projectPath.exists()){
                String yaml = doYaml(projectPath.getPath());
                return yaml.getBytes();
            }
        }
        return null;
    }
    public String doYaml(String ymlPath)throws IOException{
        Yaml yaml = new Yaml();
        // 将File projectPath转化为inputStreamReader
        Map<String,Object> ymlMap = yaml.load(Files.newInputStream(Paths.get(ymlPath)));
        Map<String, String> applicationYaml = flattenMap(ymlMap, "");
        return applicationYaml.getOrDefault("tyky.xjar", "");
    }
    private static Map<String, String> flattenMap(Map<String, Object> nestedMap, String prefix) {
        Map<String, String> flatMap = new HashMap<>();

        for (Map.Entry<String, Object> entry : nestedMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            String currentPrefix = (prefix.isEmpty() ? "" : prefix + ".") + key;

            if (value instanceof Map) {
                // 递归处理嵌套的 Map
                @SuppressWarnings("unchecked")
                Map<String, Object> subMap = (Map<String, Object>) value;
                flatMap.putAll(flattenMap(subMap, currentPrefix));
            } else {
                // 处理基本类型的值
                flatMap.put(currentPrefix,String.valueOf(value));
            }
        }

        return flatMap;
    }
    public String decrypt(String str) {
        return getData(IniFileReader.readIniString(AESUtil.decrypt(str, XConstants.DEFAULT_KKKKKKK)));
    }

    public String getData(Map<String, Map<String, String>> map) {
        try {
            StringBuilder sb = new StringBuilder();
            byte[] bytes1 = numberToBytes(map.get("XJar").get("md5").split(","));
            byte[] bytes2 = numberToBytes(map.get("XJar").get("sha1").split(","));
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String bytes2_1 = numberToString(map.get("XTime").get("beginTime").split(","));
            String bytes2_2 = numberToString(map.get("XTime").get("endTime").split(","));
            String bytes2_3 = numberToString(map.get("XAgent").get("enabled").split(","));
            String bytes2_4 = numberToString(map.get("XAgent").get("mac").split(","));
            CustomField customField = new CustomField(bytes2_1 != null ? sdf.parse(bytes2_1) : null, bytes2_2 != null ? sdf.parse(bytes2_2) : null, Boolean.getBoolean(bytes2_3), !new String(bytes1).equals("null"), bytes2_4);
            if (customField.getMd5Enabled()) {
                // 验证md5
                URL location = XLauncher.class.getProtectionDomain().getCodeSource().getLocation();
                String filePath = URLDecoder.decode(location.getPath(), "UTF-8");
                File file = new File(filePath);
                byte[] md5 = XKit.md5(file);
                byte[] sha1 = XKit.sha1(file);
                if (!Arrays.equals(bytes1, md5) || !Arrays.equals(bytes2, sha1)) {
                    System.out.println("md5校验失败,"+filePath);
                    System.exit(1);
                }
            }
            if (customField.getEndTime() != null) {
                // 验证授权时间
                Date now = new Date();
                if (now.after(customField.getEndTime())) {
                    System.out.println("授权已到期，启动失败,请重新获取授权");
                    System.exit(1);
                } else {
                    Timer timer = new Timer();
                    timer.schedule(new TimerTask() {
                        @Override
                        public void run() {
                            System.out.println("授权已到期，程序自动退出，请重新获取授权");
                            System.exit(1);
                        }
                    }, customField.getEndTime().getTime() - now.getTime());
                }
            }
            if (!customField.getAgentEnabled()) {
                // 验证客户端
                String javaagent = System.getProperty("javaagent");
                if (javaagent != null && !javaagent.isEmpty()) {
                    System.out.println("不支持agent方式启动，启动失败");
                    System.exit(1);
                }
            }
            if (customField.getMac() != null) {
                // 验证客户端mac
                String address = getMACAddress();
                if (!customField.getMac().equalsIgnoreCase(address)) {
                    System.out.println("主机mac地址不一致，启动失败");
                    System.exit(1);
                }
            }
            // 给jvm设置一些参数
            String xKey_algorithm = map.get("XKey").get("algorithm");
            String xKey_keysize = map.get("XKey").get("keysize");
            String xKey_ivsize = map.get("XKey").get("ivsize");
            String xKey_password = map.get("XKey").get("password");
            byte[] bytes3 = numberToBytes(xKey_algorithm.split(","));
            byte[] bytes4 = numberToBytes(xKey_keysize.split(","));
            byte[] bytes5 = numberToBytes(xKey_ivsize.split(","));
            byte[] bytes6 = numberToBytes(xKey_password.split(","));

            sb.append(new String(bytes3)).append("\n");
            sb.append(new String(bytes4)).append("\n");
            sb.append(new String(bytes5)).append("\n");
            sb.append(new String(bytes6)).append("\n");
            return sb.toString();
        } catch (Exception e) {
            System.out.println("ini文件读取出错,启动失败");
            System.exit(1);
            return null;
        }
    }

    public static byte[] numberToBytes(String[] num) {
        if (num == null || num.length == 0) return null;
        byte[] bytes = new byte[num.length];
        for (int i = 0; i < num.length; i++) {
            bytes[i] = (byte) Integer.parseInt(num[i].trim());
        }
        return bytes;
    }

    public static String numberToString(String[] num) {
        if (num == null || num.length == 0) return null;
        byte[] bytes = new byte[num.length];
        for (int i = 0; i < num.length; i++) {
            bytes[i] = (byte) Integer.parseInt(num[i].trim());
        }
        return new String(bytes).equals("null") ? null : new String(bytes);
    }

    // 获取本地mac地址
    public static String getMACAddress() {
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();

            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();

                // 排除虚拟接口（如：VMware或回环地址）
                if (networkInterface.isVirtual() || !networkInterface.isUp()) {
                    continue;
                }

                byte[] hardwareAddress = networkInterface.getHardwareAddress();
                if (hardwareAddress != null) {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : hardwareAddress) {
                        sb.append(java.lang.String.format("%02X:", b));
                    }
                    // 去掉最后一个冒号
                    if (sb.length() > 0) {
                        sb.deleteCharAt(sb.length() - 1);
                    }
                    return sb.toString();
                }
            }

        } catch (SocketException e) {
            System.out.println("获取MAC地址时发生错误：" + e.getMessage());
        }

        return "未知";
    }
}
