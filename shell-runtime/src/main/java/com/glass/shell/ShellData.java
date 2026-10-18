package com.glass.shell;

import android.content.Context;

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
 * 壳从 assets 读取并解密。
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
    /** DEX 载荷是否 AES 加密（false = 明文存储模式） */
    boolean dexEnc = true;
    /** DEX 载荷资产名（随机名或默认名），长度应等于 dexCount */
    String[] dexAssets;
    /** DEX 载荷 SHA-256 清单（防篡改），空数组表示不校验 */
    String[] dexSha;
    /** 原 APK 的 AppComponentFactory 类名（空表示原 APK 未使用） */
    String origFactory;

    private ShellData() {
    }

    /**
     * 读取并解密配置（assets/glass.dat）。
     */
    static ShellData load(Context base) throws Exception {
        byte[] raw = readAsset(base.getAssets(), "glass.dat");

        // 3. XOR 混淆还原
        byte[] enc = xorSalt(raw);
        // 4. 解析头：前 16 字节 = AES key（已 XOR 混淆），其余为 AES 密文
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
        if (d.signSha256 != null && d.signSha256.isEmpty()) {
            d.signSha256 = null; // 引擎关闭校验时写空串，视为不校验
        }
        d.antiDebug = obj.optBoolean("antiDebug", true);
        d.antiFrida = obj.optBoolean("antiFrida", true);
        d.dexEnc = obj.optBoolean("dexEnc", true);
        d.dexAssets = splitList(obj.optString("dexAssets", ""));
        d.dexSha = splitList(obj.optString("dexSha", ""));
        d.origFactory = obj.optString("origFactory", "");
        return d;
    }

    /** 第 i 个 DEX 载荷的资产名（无映射时回退默认命名） */
    String assetName(int i) {
        if (dexAssets != null && i < dexAssets.length && !dexAssets[i].isEmpty()) {
            return dexAssets[i];
        }
        return "glass_dex_" + i + (dexEnc ? ".enc" : ".bin");
    }

    /** 第 i 个 DEX 载荷的期望 SHA-256，无则 null */
    String expectedSha(int i) {
        if (dexSha == null || i >= dexSha.length || dexSha[i].isEmpty()) {
            return null;
        }
        return dexSha[i];
    }

    private static String[] splitList(String s) {
        if (s == null || s.isEmpty()) {
            return new String[0];
        }
        return s.split(",");
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
