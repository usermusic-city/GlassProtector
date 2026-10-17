package com.glass.shell;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 壳配置读取器。
 * 加固引擎在打包时把配置 JSON 用 AES 加密后写入 assets/glass.dat，
 * 壳在 attachBaseContext 里解密读取。
 * <p>
 * 密钥藏匿策略：AES 密钥本身再经 XOR 混淆拆分存放，
 * 提高静态分析成本（防君子不防专家，这是 DEX 加密壳的固有属性）。
 */
final class ShellData {

    /** XOR 混淆盐（与引擎侧 GlassProtectorEngine 保持一致） */
    private static final int[] XOR_SALT = {0x37, 0x51, 0x6C, 0x22, 0x4F, 0x19, 0x7A, 0x63,
            0x2E, 0x58, 0x41, 0x76, 0x33, 0x6D, 0x25, 0x4B};

    /** 原始 Application 类名 */
    String origApplication;
    /** 加密 DEX 文件个数 */
    int dexCount;
    /** AES 密钥 */
    byte[] aesKey;
    /** AES IV */
    byte[] aesIv;
    /** 签名 SHA-256（十六进制，冒号分隔），为 null 表示不校验 */
    String signSha256;
    /** 是否开启反调试 */
    boolean antiDebug;
    /** 是否开启 Frida 检测 */
    boolean antiFrida;

    private ShellData() {
    }

    /**
     * 从 assets 读取并解密配置。
     */
    static ShellData load(android.content.res.AssetManager assets) throws Exception {
        byte[] raw = readAsset(assets, "glass.dat");
        // 1. XOR 混淆还原
        byte[] enc = xorSalt(raw);
        // 2. 解析头：前 16 字节 = AES key（已 XOR 混淆），其余为 AES 密文
        if (enc.length < 16) {
            throw new IllegalStateException("bad shell data");
        }
        byte[] key = new byte[16];
        System.arraycopy(enc, 0, key, 0, 16);
        byte[] cipherBody = new byte[enc.length - 16];
        System.arraycopy(enc, 16, cipherBody, 0, cipherBody.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(key)); // IV 复用 key 前 16 字节（引擎侧同规则）
        byte[] json = cipher.doFinal(cipherBody);

        JSONObject obj = new JSONObject(new String(json, StandardCharsets.UTF_8));
        ShellData d = new ShellData();
        d.origApplication = obj.getString("origApp");
        d.dexCount = obj.getInt("dexCount");
        d.aesKey = key;
        d.aesIv = key;
        d.signSha256 = obj.optString("signSha256", null);
        d.antiDebug = obj.optBoolean("antiDebug", true);
        d.antiFrida = obj.optBoolean("antiFrida", true);
        return d;
    }

    static byte[] readAsset(android.content.res.AssetManager assets, String name) throws Exception {
        InputStream in = assets.open(name);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        in.close();
        return bos.toByteArray();
    }

    static byte[] xorSalt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ XOR_SALT[i % XOR_SALT.length]);
        }
        return out;
    }
}
