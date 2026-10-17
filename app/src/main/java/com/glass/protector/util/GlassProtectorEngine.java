package com.glass.protector.util;

import android.content.Context;

import com.glass.protector.service.ProtectConfig;
import com.wind.meditor.core.FileProcesser;
import com.wind.meditor.property.AttributeItem;
import com.wind.meditor.property.ModificationProperty;
import com.wind.meditor.utils.NodeValue;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pxb.android.axml.AxmlParser;

/**
 * Glass 自研加固引擎 —— 真实现。
 * <p>
 * 加固流程：
 * 1. 解析原 APK 的 AndroidManifest.xml，读取原 Application 类名
 * 2. 把原 APK 的全部 classes*.dex 用 AES-128-CBC 加密，写入 assets/glass_dex_N.enc
 * 3. 生成壳配置（原 Application 名、AES 密钥、签名指纹、防护开关），AES 加密后写 assets/glass.dat
 * 4. 用壳 DEX（assets/shell.dex）替换 classes.dex，manifest 的 application name 改为壳入口
 * 5. zipalign 对齐
 * 6. apksigner（v1+v2）用 PKCS12 证书重签名
 * <p>
 * 运行时壳（com.glass.shell.GlassApplication）负责解密 DEX、注入 ClassLoader、
 * 替换回原 Application、执行反调试/签名校验。
 */
public class GlassProtectorEngine {

    private static final String SHELL_APP_NAME = "com.glass.shell.GlassApplication";
    private static final String CONFIG_ASSET = "glass.dat";
    private static final String DEX_ASSET_FORMAT = "glass_dex_%d.enc";
    private static final String SHELL_DEX_ASSET = "shell.dex";
    private static final String KEYSTORE_ASSET = "glass.p12";
    private static final String KEYSTORE_PASSWORD = "glass123";
    private static final String KEYSTORE_ALIAS = "glass";
    /** XOR 混淆盐，与壳 ShellData 保持一致 */
    private static final int[] XOR_SALT = {0x37, 0x51, 0x6C, 0x22, 0x4F, 0x19, 0x7A, 0x63,
            0x2E, 0x58, 0x41, 0x76, 0x33, 0x6D, 0x25, 0x4B};

    private final ProtectConfig config;
    private final List<String> logs = new ArrayList<>();
    private final Context appContext;

    public GlassProtectorEngine(ProtectConfig config) {
        this.config = config;
        this.appContext = com.glass.protector.AppContextHolder.get();
    }

    public List<String> getLogs() {
        return logs;
    }

    private void log(String msg) {
        logs.add(msg);
    }

    public String protect() throws Exception {
        logs.clear();
        log("=== Glass 加固引擎（DEX 加密壳） ===");
        log("输入: " + config.getInputApkPath());

        File input = new File(config.getInputApkPath());
        if (!input.isFile()) {
            throw new Exception("输入 APK 不存在: " + input);
        }
        String outDir = config.getOutputDir();
        ApkUtils.ensureDir(outDir);
        File workDir = new File(outDir, "glass_work_" + System.currentTimeMillis());
        ApkUtils.ensureDir(workDir.getAbsolutePath());
        File unsignedApk = new File(workDir, "unsigned.apk");
        File alignedApk = new File(workDir, "aligned.apk");
        String outName = input.getName().replace(".apk", "") + "_glass_protected.apk";
        File outApk = new File(outDir, outName);

        // 0. 壳 dex 与 keystore 从本 APP assets 释放
        File shellDex = extractAsset(SHELL_DEX_ASSET, new File(workDir, SHELL_DEX_ASSET));
        File keyStoreFile = extractAsset(KEYSTORE_ASSET, new File(workDir, KEYSTORE_ASSET));

        // 1. 解析 manifest
        log("[1/7] 解析 AndroidManifest.xml ...");
        byte[] manifestData = readZipEntry(input, "AndroidManifest.xml");
        File manifestIn = new File(workDir, "AndroidManifest.xml");
        writeBytes(manifestIn, manifestData);
        String origApp = getManifestAttr(manifestData, "application", "name");
        String acf = getManifestAttr(manifestData, "application", "appComponentFactory");
        if (acf != null && !acf.isEmpty() && !"androidx.core.app.CoreComponentFactory".equals(acf)) {
            throw new Exception("原 APK 使用了自定义 appComponentFactory(" + acf
                    + ")，Glass 引擎暂不支持，请改用 DPT 引擎");
        }
        log("  原 Application: " + (origApp == null ? "(无，使用默认)" : origApp));

        // 2. 生成 AES 密钥并加密全部 DEX
        log("[2/7] AES 加密 DEX ...");
        byte[] aesKey = new byte[16];
        new SecureRandom().nextBytes(aesKey);
        List<String> dexNames = listDexEntries(input);
        if (dexNames.isEmpty()) {
            throw new Exception("原 APK 中没有找到 DEX 文件");
        }
        List<byte[]> encDexes = new ArrayList<>();
        long totalDexBytes = 0;
        for (String dexName : dexNames) {
            byte[] dex = readZipEntry(input, dexName);
            totalDexBytes += dex.length;
            encDexes.add(aesEncrypt(aesKey, dex));
        }
        log("  加密 " + encDexes.size() + " 个 DEX，共 " + (totalDexBytes / 1024) + " KB");

        // 3. 生成壳配置
        log("[3/7] 生成壳配置 ...");
        String signSha256 = certSha256(keyStoreFile);
        JSONObject cfg = new JSONObject();
        cfg.put("origApp", origApp == null ? "" : origApp);
        cfg.put("dexCount", encDexes.size());
        cfg.put("signSha256", config.isGlassSignVerify() ? signSha256 : "");
        cfg.put("antiDebug", config.isGlassAntiDebug());
        cfg.put("antiFrida", config.isGlassAntiDebug());
        byte[] cfgEnc = buildConfigBlob(aesKey, cfg);

        // 4. 编辑 manifest：application name → 壳，extractNativeLibs=true
        log("[4/7] 改写 manifest（壳入口接管）...");
        File manifestOut = new File(workDir, "AndroidManifest_new.xml");
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.NAME, SHELL_APP_NAME));
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.EXTRACTNATIVELIBS, "true"));
        FileProcesser.processManifestFile(manifestIn.getAbsolutePath(),
                manifestOut.getAbsolutePath(), property);
        byte[] newManifest = readFile(manifestOut);

        // 5. 重打包
        log("[5/7] 重打包 APK ...");
        rebuildApk(input, unsignedApk, newManifest, shellDex, cfgEnc, encDexes);

        // 6. zipalign
        log("[6/7] zipalign 对齐 ...");
        try (RandomAccessFile raf = new RandomAccessFile(unsignedApk, "r");
             OutputStream os = new BufferedOutputStream(new FileOutputStream(alignedApk))) {
            com.iyxan23.zipalignjava.ZipAlign.alignZip(raf, os);
        }

        // 7. apksigner 签名（v1+v2）
        log("[7/7] apksigner 重签名 (v1+v2) ...");
        signApk(alignedApk, keyStoreFile, outApk);

        // 清理工作目录
        deleteRecursive(workDir);
        log("=== 加固完成: " + outApk.getAbsolutePath() + " ===");
        log("加固说明: 原 DEX 已全部 AES 加密，运行时由壳解密加载；");
        log("反调试: " + (config.isGlassAntiDebug() ? "开启" : "关闭")
                + "，签名校验: " + (config.isGlassSignVerify() ? "开启" : "关闭"));
        return outApk.getAbsolutePath();
    }

    // ---------------- manifest ----------------

    /** 用 pxb AxmlParser 从二进制 manifest 中读取属性值 */
    private static String getManifestAttr(byte[] manifest, String tag, String attrName) {
        try {
            AxmlParser parser = new AxmlParser(manifest);
            while (parser.next() != AxmlParser.END_FILE) {
                if (parser.getAttrCount() == 0) continue;
                if (!tag.equals(parser.getName())) continue;
                for (int i = 0; i < parser.getAttrCount(); i++) {
                    if (parser.getAttrName(i).equals(attrName)) {
                        Object v = parser.getAttrValue(i);
                        return v == null ? null : String.valueOf(v);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    // ---------------- 加密 ----------------

    private static byte[] aesEncrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(key));
        return cipher.doFinal(data);
    }

    /** 配置 JSON → AES 加密 → 头部拼 key → XOR 混淆（壳侧按相反顺序还原） */
    private static byte[] buildConfigBlob(byte[] aesKey, JSONObject cfg) throws Exception {
        byte[] cipherBody = aesEncrypt(aesKey, cfg.toString().getBytes(StandardCharsets.UTF_8));
        byte[] blob = new byte[16 + cipherBody.length];
        System.arraycopy(aesKey, 0, blob, 0, 16);
        System.arraycopy(cipherBody, 0, blob, 16, cipherBody.length);
        byte[] out = new byte[blob.length];
        for (int i = 0; i < blob.length; i++) {
            out[i] = (byte) (blob[i] ^ XOR_SALT[i % XOR_SALT.length]);
        }
        return out;
    }

    // ---------------- 重打包 ----------------

    /**
     * 流式重打包：原样复制所有 entry（保持 STORED/DEFLATED 与时间戳），
     * 跳过旧 DEX 与旧签名，替换 manifest，追加壳 DEX 与加密 DEX。
     */
    private void rebuildApk(File input, File output, byte[] newManifest, File shellDex,
                            byte[] configBlob, List<byte[]> encDexes) throws Exception {
        try (ZipFile zip = new ZipFile(input);
             ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(output)))) {

            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (name.startsWith("classes") && name.endsWith(".dex")) continue;      // 旧 DEX
                if (name.equals("AndroidManifest.xml")) continue;                        // 换新 manifest
                if (name.startsWith("META-INF/")
                        && (name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA")
                        || name.endsWith(".EC") || name.endsWith(".MF"))) continue;       // 旧签名

                copyEntry(zip, zos, e);
            }

            // 新 manifest
            putEntry(zos, "AndroidManifest.xml", newManifest, ZipEntry.DEFLATED);
            // 壳 DEX 作为主 DEX
            putEntry(zos, "classes.dex", readFile(shellDex), ZipEntry.DEFLATED);
            // 配置
            putEntry(zos, "assets/" + CONFIG_ASSET, configBlob, ZipEntry.DEFLATED);
            // 加密 DEX
            for (int i = 0; i < encDexes.size(); i++) {
                putEntry(zos, String.format(Locale.US, "assets/" + DEX_ASSET_FORMAT, i),
                        encDexes.get(i), ZipEntry.DEFLATED);
            }
        }
    }

    private static void copyEntry(ZipFile zip, ZipOutputStream zos, ZipEntry e) throws Exception {
        ZipEntry out = new ZipEntry(e.getName());
        out.setTime(e.getTime());
        if (e.getMethod() == ZipEntry.STORED) {
            // resources.arsc 等 STORED 条目必须保持不压缩（targetSdk 30+ 安装要求）
            out.setMethod(ZipEntry.STORED);
            out.setSize(e.getSize());
            out.setCompressedSize(e.getSize());
            out.setCrc(e.getCrc());
        }
        zos.putNextEntry(out);
        try (InputStream in = zip.getInputStream(e)) {
            transfer(in, zos);
        }
        zos.closeEntry();
    }

    private static void putEntry(ZipOutputStream zos, String name, byte[] data, int method) throws Exception {
        ZipEntry e = new ZipEntry(name);
        e.setTime(System.currentTimeMillis());
        if (method == ZipEntry.STORED) {
            e.setMethod(ZipEntry.STORED);
            e.setSize(data.length);
            e.setCompressedSize(data.length);
            e.setCrc(crc32(data));
        }
        zos.putNextEntry(e);
        zos.write(data);
        zos.closeEntry();
    }

    // ---------------- 签名 ----------------

    private void signApk(File in, File keyStore, File out) throws Exception {
        // apksigner 的 main 会把结果打在 stdout；错误会抛异常
        com.android.apksigner.ApkSignerTool.main(new String[]{
                "sign",
                "--ks", keyStore.getAbsolutePath(),
                "--ks-pass", "pass:" + KEYSTORE_PASSWORD,
                "--key-pass", "pass:" + KEYSTORE_PASSWORD,
                "--ks-key-alias", KEYSTORE_ALIAS,
                "--v1-signing-enabled", "true",
                "--v2-signing-enabled", "true",
                "--v3-signing-enabled", "false",
                "--out", out.getAbsolutePath(),
                in.getAbsolutePath()
        });
        if (!out.isFile() || out.length() == 0) {
            throw new Exception("签名失败：输出 APK 不存在");
        }
    }

    /** 计算 keystore 证书 SHA-256（冒号分隔大写 hex），壳运行时用它做签名校验 */
    private static String certSha256(File p12) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(p12)) {
            ks.load(in, KEYSTORE_PASSWORD.toCharArray());
        }
        java.security.cert.Certificate cert = ks.getCertificate(KEYSTORE_ALIAS);
        if (cert == null) {
            throw new Exception("keystore 中没有别名 " + KEYSTORE_ALIAS);
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", digest[i]));
        }
        return sb.toString();
    }

    // ---------------- IO 工具 ----------------

    private List<String> listDexEntries(File apk) throws Exception {
        List<String> names = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String n = e.getName();
                if (n.startsWith("classes") && n.endsWith(".dex")) {
                    names.add(n);
                }
            }
        }
        names.sort((a, b) -> {
            int ia = dexIndex(a), ib = dexIndex(b);
            return Integer.compare(ia, ib);
        });
        return names;
    }

    private static int dexIndex(String name) {
        // classes.dex -> 0, classes2.dex -> 1 ...
        try {
            String s = name.replace("classes", "").replace(".dex", "");
            return s.isEmpty() ? 0 : Integer.parseInt(s) - 1;
        } catch (NumberFormatException e) {
            return Integer.MAX_VALUE;
        }
    }

    private static byte[] readZipEntry(File apk, String entryName) throws Exception {
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry e = zip.getEntry(entryName);
            if (e == null) return null;
            try (InputStream in = zip.getInputStream(e)) {
                return readAll(in);
            }
        }
    }

    /** 从本 APP 的 assets 释放文件 */
    private File extractAsset(String assetName, File dest) throws Exception {
        if (appContext == null) {
            throw new Exception("Application context 不可用，无法释放内置资源 " + assetName);
        }
        try (InputStream in = appContext.getAssets().open(assetName)) {
            writeBytes(dest, readAll(in));
        }
        return dest;
    }

    private static void writeBytes(File f, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(data);
        }
    }

    private static byte[] readFile(File f) throws Exception {
        try (InputStream in = new FileInputStream(f)) {
            return readAll(in);
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    private static void transfer(InputStream in, OutputStream out) throws Exception {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
    }

    private static long crc32(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return crc.getValue();
    }

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) deleteRecursive(c);
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }
}
