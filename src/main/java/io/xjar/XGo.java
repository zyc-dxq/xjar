package io.xjar;

import io.xjar.key.XKey;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * XJar GoLang 启动器
 *
 * @author Payne 646742615@qq.com
 * 2020/4/6 18:20
 */
public class XGo {
    private static final String CLRF = System.getProperty("line.separator");
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public static void make(File xJar, XKey xKey) throws IOException {
        byte[] md5 = null;
        byte[] sha1 = null;
        if(xKey.getCustomField().getMd5Enabled()){
            md5 = XKit.md5(xJar);
            sha1 = XKit.sha1(xJar);
        }else {
            md5 = "null".getBytes(StandardCharsets.UTF_8);
            sha1 = "null".getBytes(StandardCharsets.UTF_8);
        }
        byte[] algorithm = xKey.getAlgorithm().getBytes(StandardCharsets.UTF_8);
        byte[] keysize = String.valueOf(xKey.getKeysize()).getBytes(StandardCharsets.UTF_8);
        byte[] ivsize = String.valueOf(xKey.getIvsize()).getBytes(StandardCharsets.UTF_8);
        byte[] password = xKey.getPassword().getBytes(StandardCharsets.UTF_8);
        byte[] beginTime = (xKey.getCustomField().getBeginTime() != null ? sdf.format(xKey.getCustomField().getBeginTime()) : "null").getBytes(StandardCharsets.UTF_8);
        byte[] endTime = (xKey.getCustomField().getEndTime() !=null ? sdf.format(xKey.getCustomField().getEndTime()) : "null").getBytes(StandardCharsets.UTF_8);
        byte[] agentEnabled = (xKey.getCustomField().getAgentEnabled() !=null ? xKey.getCustomField().getAgentEnabled().toString() : "null").getBytes(StandardCharsets.UTF_8);
        byte[] mac = (xKey.getCustomField().getMac() !=null ? xKey.getCustomField().getMac(): "null").getBytes(StandardCharsets.UTF_8);

        Map<String, String> variables = new HashMap<>();
        variables.put("xJar.md5", convert(md5));
        variables.put("xJar.sha1", convert(sha1));
        variables.put("xKey.algorithm", convert(algorithm));
        variables.put("xKey.keysize", convert(keysize));
        variables.put("xKey.ivsize", convert(ivsize));
        variables.put("xKey.password", convert(password));
        variables.put("xTime.beginTime", convert(beginTime));
        variables.put("xTime.endTime", convert(endTime));
        variables.put("xAgent.enabled", convert(agentEnabled));
        variables.put("xAgent.mac", convert(mac));

        List<String> templates = Arrays.asList("xjar.go", "xjar_agentable.go","config.ini");
        templates = Arrays.asList("config.ini");
        for (String template : templates) {
            URL url = XGo.class.getClassLoader().getResource("xjar/" + template);
            if (url == null) {
                throw new IOException("could not find xjar/" + template + " in classpath");
            }
            String dir = xJar.getParent();
            File src = new File(dir, template);
            try (
                    InputStream in = url.openStream();
                    Reader reader = new InputStreamReader(in);
                    BufferedReader br = new BufferedReader(reader);
                    OutputStream out = new FileOutputStream(src);
                    Writer writer = new OutputStreamWriter(out);
                    BufferedWriter bw = new BufferedWriter(writer)
            ) {
                String line;
                StringBuilder textStr = new StringBuilder();
                if ("config.ini".equals(template)) {
                    while ((line = br.readLine()) != null) {
                        for (Map.Entry<String, String> variable : variables.entrySet()) {
                            line = line.replace("#{" + variable.getKey() + "}", variable.getValue());
                        }
                        textStr.append(line).append(CLRF);
                    }
                    bw.write(AESUtil.encrypt(textStr.toString(), XConstants.DEFAULT_KKKKKKK));
                } else {
                    while ((line = br.readLine()) != null) {
                        for (Map.Entry<String, String> variable : variables.entrySet()) {
                            line = line.replace("#{" + variable.getKey() + "}", variable.getValue());
                        }
                        bw.write(line);
                        bw.write(CLRF);
                    }
                }
                bw.flush();
                writer.flush();
                out.flush();
            }
        }
    }

    private static String convert(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(b & 0xFF);
        }
        return builder.toString();
    }

}
