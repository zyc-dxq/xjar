package io.xjar;

import io.xjar.key.Validate;
import io.xjar.key.XKey;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * Spring-Boot 启动器
 *
 * @author Payne 646742615@qq.com
 * 2019/4/14 10:28
 */
public class XLauncher implements XConstants {
    public final String[] args;
    public final XDecryptor xDecryptor;
    public final XEncryptor xEncryptor;
    public final XKey xKey;

    //    public XLauncher(String... args) throws Exception {
//        this.args = args;
//        Scanner scanner = new Scanner(System.in);
//        String algorithm = scanner.nextLine();
//        int keysize = Integer.parseInt(scanner.nextLine());
//        int ivsize = Integer.parseInt(scanner.nextLine());
//        String password = scanner.nextLine();
//        this.xDecryptor = new XJdkDecryptor();
//        this.xEncryptor = new XJdkEncryptor();
//        this.xKey = XKit.key(algorithm, keysize, ivsize, password);
//    }
    public XLauncher(String... args) throws Exception {
        this.args = args;
        String validateStr = new Validate().validate();
        InputStream is = new ByteArrayInputStream(validateStr.getBytes(StandardCharsets.UTF_8));
        Scanner scanner = new Scanner(is);
        String algorithm = scanner.nextLine();
        int keysize = Integer.parseInt(scanner.nextLine());
        int ivsize = Integer.parseInt(scanner.nextLine());
        String password = scanner.nextLine();
        this.xDecryptor = new XJdkDecryptor();
        this.xEncryptor = new XJdkEncryptor();
        this.xKey = XKit.key(algorithm, keysize, ivsize, password);
    }

}
