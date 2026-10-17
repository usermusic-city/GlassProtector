package com.luoye.dpt.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 消息摘要工具类 - 从dpt-shell移植
 */
public class MessageDigestUtils {

    /**
     * MD5摘要
     */
    public static byte[] md5(byte[] data) {
        return digest(data, "MD5");
    }

    /**
     * SHA-1摘要
     */
    public static byte[] sha1(byte[] data) {
        return digest(data, "SHA-1");
    }

    /**
     * SHA-256摘要
     */
    public static byte[] sha256(byte[] data) {
        return digest(data, "SHA-256");
    }

    /**
     * 文件SHA-256摘要
     */
    public static byte[] sha256File(File file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, len);
                }
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 文件MD5摘要
     */
    public static String md5File(File file) throws IOException {
        return HexUtils.bytesToHex(sha256File(file)); // 复用文件读取逻辑
    }

    private static byte[] digest(byte[] data, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(algorithm + " not available", e);
        }
    }

    /**
     * 摘要转十六进制字符串
     */
    public static String sha256Hex(byte[] data) {
        return HexUtils.bytesToHex(sha256(data));
    }

    public static String md5Hex(byte[] data) {
        return HexUtils.bytesToHex(md5(data));
    }
}
