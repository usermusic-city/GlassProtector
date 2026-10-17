package com.luoye.dpt.util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * 加密工具类 - 从dpt-shell移植
 * 修复bug: 1. AES加密填充方式统一为PKCS5Padding 2. IV生成使用SecureRandom 3. 修复密钥长度校验
 */
public class CryptoUtils {

    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String AES_KEY_ALGORITHM = "AES";

    /**
     * AES加密
     */
    public static byte[] aesEncrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        if (key == null || key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24, or 32 bytes");
        }
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("IV must be 16 bytes");
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, AES_KEY_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    /**
     * AES解密
     */
    public static byte[] aesDecrypt(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, AES_KEY_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(encryptedData);
    }

    /**
     * 生成随机AES密钥
     */
    public static byte[] generateAesKey(int keySize) {
        byte[] key = new byte[keySize / 8];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * 生成随机IV
     */
    public static byte[] generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * XOR加密
     */
    public static byte[] xorEncrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    /**
     * RC4加密
     */
    public static byte[] rc4(byte[] data, byte[] key) {
        int[] s = new int[256];
        int i, j = 0, k;
        byte[] result = new byte[data.length];

        for (i = 0; i < 256; i++) {
            s[i] = i;
        }
        for (i = 0; i < 256; i++) {
            j = (j + s[i] + key[i % key.length]) & 0xFF;
            int temp = s[i];
            s[i] = s[j];
            s[j] = temp;
        }

        i = 0;
        j = 0;
        for (k = 0; k < data.length; k++) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            int temp = s[i];
            s[i] = s[j];
            s[j] = temp;
            result[k] = (byte) (data[k] ^ s[(s[i] + s[j]) & 0xFF]);
        }
        return result;
    }
}
