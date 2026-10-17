package com.glass.protector.util;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * 签名秘钥管理工具
 * 支持 JKS (Java KeyStore) 和 BKS (Bouncy Castle KeyStore) 两种格式
 *
 * JKS: Java标准密钥库，使用JKS算法，通常用于Android签名
 * BKS: Bouncy Castle密钥库，使用BKS算法，部分旧版Android使用
 */
public class KeyStoreUtils {

    private static final String TAG = "KeyStoreUtils";

    public enum KeyStoreType {
        JKS("JKS"),
        BKS("BKS"),
        PKCS12("PKCS12");

        private final String type;
        KeyStoreType(String type) { this.type = type; }
        public String getType() { return type; }
    }

    /**
     * 根据文件扩展名自动判断秘钥类型
     */
    public static KeyStoreType detectType(String filePath) {
        if (filePath == null) return KeyStoreType.JKS;
        String lower = filePath.toLowerCase();
        if (lower.endsWith(".bks")) return KeyStoreType.BKS;
        if (lower.endsWith(".p12") || lower.endsWith(".pfx")) return KeyStoreType.PKCS12;
        return KeyStoreType.JKS; // .jks 或其他默认JKS
    }

    /**
     * 加载秘钥库
     */
    public static KeyStore loadKeyStore(String keystorePath, String password, KeyStoreType type)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type.getType());
        try (InputStream is = new FileInputStream(keystorePath)) {
            keyStore.load(is, password != null ? password.toCharArray() : null);
        }
        return keyStore;
    }

    /**
     * 验证秘钥密码是否正确
     */
    public static boolean verifyPassword(String keystorePath, String password, KeyStoreType type) {
        try {
            loadKeyStore(keystorePath, password, type);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "秘钥密码验证失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 获取秘钥库中的所有别名
     */
    public static String[] getAliases(String keystorePath, String password, KeyStoreType type) {
        try {
            KeyStore keyStore = loadKeyStore(keystorePath, password, type);
            Enumeration<String> aliases = keyStore.aliases();
            java.util.List<String> list = new java.util.ArrayList<>();
            while (aliases.hasMoreElements()) {
                list.add(aliases.nextElement());
            }
            return list.toArray(new String[0]);
        } catch (Exception e) {
            Log.e(TAG, "获取别名失败: " + e.getMessage());
            return new String[0];
        }
    }

    /**
     * 获取私钥
     */
    public static PrivateKey getPrivateKey(String keystorePath, String password,
                                            String alias, String keyPassword, KeyStoreType type) {
        try {
            KeyStore keyStore = loadKeyStore(keystorePath, password, type);
            char[] keyPass = keyPassword != null ? keyPassword.toCharArray() :
                    (password != null ? password.toCharArray() : null);
            return (PrivateKey) keyStore.getKey(alias, keyPass);
        } catch (Exception e) {
            Log.e(TAG, "获取私钥失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 获取证书链
     */
    public static Certificate[] getCertificateChain(String keystorePath, String password,
                                                     String alias, KeyStoreType type) {
        try {
            KeyStore keyStore = loadKeyStore(keystorePath, password, type);
            return keyStore.getCertificateChain(alias);
        } catch (Exception e) {
            Log.e(TAG, "获取证书链失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 验证秘钥文件是否有效
     */
    public static boolean isValidKeystore(String keystorePath) {
        if (keystorePath == null) return false;
        File file = new File(keystorePath);
        if (!file.exists() || !file.isFile()) return false;
        String lower = keystorePath.toLowerCase();
        return lower.endsWith(".jks") || lower.endsWith(".bks") ||
                lower.endsWith(".keystore") || lower.endsWith(".p12") || lower.endsWith(".pfx");
    }

    /**
     * 从Context的assets中加载内置默认秘钥（用于Debug签名）
     */
    public static KeyStore loadDefaultDebugKeystore(Context context) {
        try {
            // Android默认debug keystore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream is = context.getAssets().open("debug.keystore")) {
                keyStore.load(is, "android".toCharArray());
            }
            return keyStore;
        } catch (IOException e) {
            // 如果assets中没有，使用系统默认debug keystore
            try {
                File debugKeystore = new File(System.getProperty("user.home"), ".android/debug.keystore");
                if (debugKeystore.exists()) {
                    KeyStore keyStore = KeyStore.getInstance("JKS");
                    try (InputStream is = new FileInputStream(debugKeystore)) {
                        keyStore.load(is, "android".toCharArray());
                    }
                    return keyStore;
                }
            } catch (Exception ex) {
                Log.e(TAG, "加载默认debug秘钥失败: " + ex.getMessage());
            }
            return null;
        } catch (Exception e) {
            Log.e(TAG, "加载默认debug秘钥失败: " + e.getMessage());
            return null;
        }
    }
}
