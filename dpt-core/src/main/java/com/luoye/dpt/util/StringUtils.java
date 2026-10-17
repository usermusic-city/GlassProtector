package com.luoye.dpt.util;

import java.nio.charset.StandardCharsets;

/**
 * 字符串工具类 - 从dpt-shell移植，修复了中文编码bug
 */
public class StringUtils {

    /**
     * 判断字符串是否为空
     */
    public static boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }

    /**
     * 判断字符串是否不为空
     */
    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * 字符串转字节数组（UTF-8）
     * 修复bug: 原版使用默认编码，中文会乱码
     */
    public static byte[] stringToBytes(String str) {
        if (str == null) return null;
        return str.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 字节数组转字符串（UTF-8）
     */
    public static String bytesToString(byte[] bytes) {
        if (bytes == null) return null;
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * 字符串XOR加密
     */
    public static String xorEncrypt(String str, String key) {
        if (str == null || key == null || key.isEmpty()) return str;
        byte[] strBytes = stringToBytes(str);
        byte[] keyBytes = stringToBytes(key);
        byte[] result = new byte[strBytes.length];
        for (int i = 0; i < strBytes.length; i++) {
            result[i] = (byte) (strBytes[i] ^ keyBytes[i % keyBytes.length]);
        }
        return HexUtils.bytesToHex(result);
    }

    /**
     * 字符串XOR解密
     */
    public static String xorDecrypt(String hex, String key) {
        if (hex == null || key == null || key.isEmpty()) return hex;
        byte[] encrypted = HexUtils.hexToBytes(hex);
        byte[] keyBytes = stringToBytes(key);
        byte[] result = new byte[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            result[i] = (byte) (encrypted[i] ^ keyBytes[i % keyBytes.length]);
        }
        return bytesToString(result);
    }

    /**
     * 首字母大写
     */
    public static String capitalize(String str) {
        if (isEmpty(str)) return str;
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

    /**
     * 重复字符串
     */
    public static String repeat(String str, int count) {
        if (str == null || count <= 0) return "";
        StringBuilder sb = new StringBuilder(str.length() * count);
        for (int i = 0; i < count; i++) {
            sb.append(str);
        }
        return sb.toString();
    }
}
