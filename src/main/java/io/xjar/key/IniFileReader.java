package io.xjar.key;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class IniFileReader {

    public static Map<String, Map<String, String>> readIniFile(String filePath) {
        try {
            FileReader fileReader = new FileReader(filePath);
            return readIni(fileReader);
        } catch (IOException e) {
            return null;
        }
    }

    public static Map<String, Map<String, String>> readIniString(String content) {
        StringReader stringReader = new StringReader(content);
        return readIni(stringReader);
    }

    public static Map<String, Map<String, String>> readIni(Reader isr) {
        Map<String, Map<String, String>> iniContent = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(isr)) {
            String line;
            String currentSection = null;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith(";") || line.startsWith("#")) {
                    // 忽略空行、注释行
                    continue;
                } else if (line.startsWith("[")) {
                    // 遇到新的section
                    currentSection = line.substring(1, line.length() - 1);
                    iniContent.put(currentSection, new HashMap<String, String>());
                } else {
                    int equalIndex = line.indexOf('=');
                    if (equalIndex > 0) {
                        String key = line.substring(0, equalIndex).trim();
                        String value = line.substring(equalIndex + 1).trim();
                        if (value.startsWith("\"")) {
                            value = value.replace("\"", "");
                        }
                        if (value.endsWith("\"")) {
                            value = value.replace("\"", "");
                        }

                        iniContent.get(currentSection).put(key, value);
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return iniContent;
    }
}
