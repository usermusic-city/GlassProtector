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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pxb.android.axml.AxmlParser;

import com.android.apksig.ApkSigner;

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
    /** 壳代理 AppComponentFactory（API 28+，接管原 factory） */
    private static final String SHELL_FACTORY_NAME = "com.glass.shell.GlassAppComponentFactory";
    private static final String CONFIG_ASSET = "glass.dat";
    private static final String DEX_ASSET_FORMAT = "glass_dex_%d.enc";
    private static final String SHELL_DEX_ASSET = "shell.dex";
    private static final String JUNK_DEX_ASSET = "junk.dex";
    private static final String KEYSTORE_ASSET = "glass.p12";
    private static final String KEYSTORE_PASSWORD = "glass123";
    private static final String KEYSTORE_ALIAS = "glass";
    /** 资源混淆：全部条目时间戳归零到 DOS 纪元 1980-01-01（防时间线取证） */
    private static final long META_SCRUB_TIME = 315532800000L;
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
        File outApk = uniqueFile(new File(outDir, outName));

        // 0. 壳 dex 与 keystore 从本 APP assets 释放；用户配置了自定义签名秘钥则优先使用
        File shellDex = extractAsset(SHELL_DEX_ASSET, new File(workDir, SHELL_DEX_ASSET));
        File keyStoreFile;
        String signStorePass, signAlias, signKeyPass;
        if (config.hasCustomKeystore()) {
            keyStoreFile = new File(config.getKeystorePath());
            signStorePass = config.getKeystorePass() == null ? "" : config.getKeystorePass();
            signAlias = config.getKeystoreAlias() == null ? "" : config.getKeystoreAlias();
            // 别名密码未单独填写时回退秘钥库密码（PKCS12/JKS 常见两者相同）
            signKeyPass = (config.getKeystoreAliasPass() == null || config.getKeystoreAliasPass().isEmpty())
                    ? signStorePass : config.getKeystoreAliasPass();
            String vErr = KeyStoreUtils.verifyKeystore(keyStoreFile.getAbsolutePath(),
                    signStorePass, signAlias, signKeyPass);
            if (vErr != null) {
                throw new Exception("自定义签名秘钥校验失败：" + vErr);
            }
            log("  签名秘钥: 自定义 " + keyStoreFile.getName() + "（alias=" + signAlias + "）");
        } else {
            keyStoreFile = extractAsset(KEYSTORE_ASSET, new File(workDir, KEYSTORE_ASSET));
            signStorePass = KEYSTORE_PASSWORD;
            signAlias = KEYSTORE_ALIAS;
            signKeyPass = KEYSTORE_PASSWORD;
            log("  签名秘钥: 内置默认秘钥（可在设置页配置自定义秘钥）");
        }

        // 1. 解析 manifest
        log("[1/8] 解析 AndroidManifest.xml ...");
        byte[] manifestData = readZipEntry(input, "AndroidManifest.xml");
        File manifestIn = new File(workDir, "AndroidManifest.xml");
        writeBytes(manifestIn, manifestData);
        String origApp = getManifestAttr(manifestData, "application", "name");
        String acf = getManifestAttr(manifestData, "application", "appComponentFactory");
        boolean hasAcf = acf != null && !acf.isEmpty();
        if (hasAcf) {
            log("  自定义 appComponentFactory: " + acf + "（壳代理接管）");
        }
        log("  原 Application: " + (origApp == null ? "(无，使用默认)" : origApp));

        // 2. 生成 AES 密钥并处理全部 DEX（流式落盘，不整块进内存）
        boolean dexEnc = config.isDexEncrypt();
        log("[2/8] " + (dexEnc ? "AES 加密 DEX ..." : "DEX 明文存储（dexEncrypt 关闭）..."));
        byte[] aesKey = new byte[16];
        new SecureRandom().nextBytes(aesKey);
        List<String> dexNames = listDexEntries(input);
        if (dexNames.isEmpty()) {
            throw new Exception("原 APK 中没有找到 DEX 文件");
        }
        List<EncDex> encDexes = new ArrayList<>();
        long totalDexBytes = 0;
        for (int i = 0; i < dexNames.size(); i++) {
            String dexName = dexNames.get(i);
            File encFile = new File(workDir, "payload_" + i + (dexEnc ? ".enc" : ".bin"));
            EncDex info = dexEnc
                    ? encryptDexToFile(input, dexName, aesKey, encFile)
                    : copyDexToFile(input, dexName, encFile);
            info.assetName = dexAssetName(i, config.isGlassStringEncrypt(), dexEnc);
            info.sha256 = sha256File(encFile);
            encDexes.add(info);
            totalDexBytes += info.origSize;
            log("  " + dexName + " (" + (info.origSize / 1024) + " KB) "
                    + (dexEnc ? "已加密" : "明文保留") + " → assets/" + info.assetName);
        }
        log("  共处理 " + encDexes.size() + " 个 DEX，合计 " + (totalDexBytes / 1024) + " KB"
                + (dexEnc ? "" : "（明文模式）"));

        // 3. 壳配置字段（JSON 统一序列化，避免字段丢失）
        log("[3/8] 生成壳配置 ...");
        String signSha256 = certSha256(keyStoreFile, signStorePass, signAlias);
        JSONObject cfg = new JSONObject();
        cfg.put("origApp", origApp == null ? "" : origApp);
        cfg.put("origFactory", hasAcf ? acf : "");
        cfg.put("dexCount", encDexes.size());
        cfg.put("signSha256", config.isGlassSignVerify() ? signSha256 : "");
        cfg.put("antiDebug", config.isGlassAntiDebug());
        cfg.put("antiFrida", config.isGlassAntiDebug());
        cfg.put("dexEnc", dexEnc);
        // 资产名映射（随机名或默认名）+ 完整性校验清单（防篡改，壳加载前逐一核对）
        StringBuilder namesSb = new StringBuilder();
        StringBuilder shasSb = new StringBuilder();
        for (int i = 0; i < encDexes.size(); i++) {
            if (i > 0) { namesSb.append(','); shasSb.append(','); }
            namesSb.append(encDexes.get(i).assetName);
            shasSb.append(encDexes.get(i).sha256);
        }
        cfg.put("dexAssets", namesSb.toString());
        cfg.put("dexSha", shasSb.toString());
        if (config.isGlassStringEncrypt()) {
            log("  资产名随机化: DEX 资产名已随机化（glass_dex_N → 随机 8 位 hex），映射藏于加密配置");
        }

        // 4. 编辑 manifest：application name → 壳，extractNativeLibs=true
        log("[5/8] 改写 manifest（壳入口接管）...");
        File manifestOut = new File(workDir, "AndroidManifest_new.xml");
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.NAME, SHELL_APP_NAME));
        if (hasAcf) {
            // 原 factory 类名存入壳配置，manifest 指向壳代理工厂
            property.addApplicationAttribute(new AttributeItem("appComponentFactory", SHELL_FACTORY_NAME));
        }
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.EXTRACTNATIVELIBS, "true"));
        FileProcesser.processManifestFile(manifestIn.getAbsolutePath(),
                manifestOut.getAbsolutePath(), property);
        byte[] newManifest = readFile(manifestOut);

        // 5.5 序列化壳配置（在字段写入之后，修复字段丢失）
        byte[] cfgEnc = buildConfigBlob(aesKey, cfg);

        // 5.7 垃圾代码：释放预编译 junk dex（不透明谓词 + 控制流平坦化）
        File junkDex = null;
        if (config.isGlassJunkCode()) {
            try {
                junkDex = extractAsset(JUNK_DEX_ASSET, new File(workDir, JUNK_DEX_ASSET));
            } catch (Exception e) {
                log("  [warn] junk.dex 资产缺失，垃圾代码注入跳过（需 CI 构建携带）");
            }
        }

        // 6. 重打包
        log("[6/8] 重打包 APK ...");
        rebuildApk(input, unsignedApk, newManifest, shellDex, cfgEnc, encDexes,
                junkDex, elfSo64, elfSo32, config.isResourceObfuscate(), dexNames.size());

        // 7. zipalign
        log("[7/8] zipalign 对齐 ...");
        try (RandomAccessFile raf = new RandomAccessFile(unsignedApk, "r");
             OutputStream os = new BufferedOutputStream(new FileOutputStream(alignedApk))) {
            com.iyxan23.zipalignjava.ZipAlign.alignZip(raf, os);
        }

        // 8. apksigner 签名（v1+v2）
        log("[8/8] apksigner 重签名 (v1+v2) ...");
        signApk(alignedApk, keyStoreFile, outApk, signStorePass, signAlias, signKeyPass);

        // 清理工作目录
        deleteRecursive(workDir);
        // 清理 cache 中的输入 APK 副本（文件选择器复制产生，防堆积）
        try {
            File cacheDir = appContext != null ? appContext.getCacheDir() : null;
            if (cacheDir != null && input.getParentFile() != null
                    && cacheDir.getAbsolutePath().equals(input.getParentFile().getAbsolutePath())
                    && input.delete()) {
                log("已自动清理输入缓存副本: " + input.getName());
            }
        } catch (Throwable ignored) {
        }
        log("=== 加固完成: " + outApk.getAbsolutePath() + " ===");
        log("加固说明: 原 DEX 已" + (dexEnc ? "全部 AES 加密，运行时由壳解密加载" : "明文存储（dexEncrypt 关闭）")
                + "；加载前逐一 SHA-256 完整性校验；");
        log("反调试: " + (config.isGlassAntiDebug() ? "开启" : "关闭")
                + "，签名校验: " + (config.isGlassSignVerify() ? "开启" : "关闭")
                + "，资产名随机化: " + (config.isGlassStringEncrypt() ? "开启" : "关闭"));
        log("资源混淆(路径+arsc+元数据): " + (config.isResourceObfuscate() ? "开启" : "关闭")
                + "，垃圾代码(junk dex): " + (config.isGlassJunkCode() ? "开启" : "关闭"));
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
     * 流式重打包：原样复制所有 entry（保持 STORED/DEFLATED），
     * 跳过旧 DEX 与旧签名，替换 manifest，追加壳 DEX、加密 DEX、
     * junk dex 与 ELF 配置容器。
     */
    private void rebuildApk(File input, File output, byte[] newManifest, File shellDex,
                            byte[] configBlob, List<EncDex> encDexes,
                            File junkDex,
                            byte[] elfSo64, byte[] elfSo32,
                            boolean scrubMeta, int origDexCount) throws Exception {
        try (ZipFile zip = new ZipFile(input);
             ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(output)))) {

            // ---- res 资源混淆：arsc 字符串池（路径/type名/entry名）+ manifest 同步 + 条目改名映射 ----
            byte[] manifestOut = newManifest;
            byte[] arscOut = null;
            Map<String, String> resPathMap = null;
            if (scrubMeta) {
                Set<String> allNames = new HashSet<>();
                Enumeration<? extends ZipEntry> it0 = zip.entries();
                while (it0.hasMoreElements()) allNames.add(it0.nextElement().getName());
                byte[] arsc = readZipBytes(zip, "resources.arsc");
                if (arsc != null) {
                    ArscObfuscator.Result r = ArscObfuscator.obfuscate(arsc, manifestOut, allNames);
                    arscOut = r.arsc;
                    manifestOut = r.manifest;
                    resPathMap = r.pathMap;
                    log("  资源混淆: " + r.obfPaths + " 个资源路径已随机化，"
                            + r.obfTypeNames + " 个 type 名 / " + r.obfKeyNames
                            + " 个 entry 名已混淆（arsc 等长原地替换）");
                }
            }

            int scrubbed = 0;
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (name.startsWith("classes") && name.endsWith(".dex")) continue;      // 旧 DEX
                if (name.equals("AndroidManifest.xml")) continue;                        // 换新 manifest
                if (name.startsWith("META-INF/")
                        && (name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA")
                        || name.endsWith(".EC") || name.endsWith(".MF"))) continue;       // 旧签名
                if (name.equals("resources.arsc")) {
                    // arsc：混淆后内容已变，必须重算 CRC（putEntry 内置）；保持 STORED
                    if (arscOut != null) {
                        putEntry(zos, name, arscOut, ZipEntry.STORED,
                                scrubMeta ? META_SCRUB_TIME : System.currentTimeMillis());
                    } else {
                        copyEntry(zip, zos, e, scrubMeta, null);
                        if (scrubMeta) scrubbed++;
                    }
                    continue;
                }
                if (resPathMap != null && resPathMap.containsKey(name)) {
                    // res 资源文件：按 arsc 同一映射改名（内容不变，CRC 不变）
                    copyEntry(zip, zos, e, scrubMeta, resPathMap.get(name));
                    if (scrubMeta) scrubbed++;
                    continue;
                }

                copyEntry(zip, zos, e, scrubMeta, null);
                if (scrubMeta) scrubbed++;
            }
            if (scrubMeta) {
                log("  资源混淆: " + scrubbed + " 个原条目时间戳已清零(1980-01-01)、extra 已剥离");
            }

            long ts = scrubMeta ? META_SCRUB_TIME : System.currentTimeMillis();
            // 新 manifest
            putEntry(zos, "AndroidManifest.xml", manifestOut, ZipEntry.DEFLATED, ts);
            // 壳 DEX 作为主 DEX
            putEntry(zos, "classes.dex", readFile(shellDex), ZipEntry.DEFLATED, ts);
            // 配置
            putEntry(zos, "assets/" + CONFIG_ASSET, configBlob, ZipEntry.DEFLATED, ts);
            // DEX 载荷（从落盘文件流式写入；密文不可压缩，用 STORED 免去无谓 CPU）
            for (int i = 0; i < encDexes.size(); i++) {
                EncDex d = encDexes.get(i);
                putFileEntry(zos, "assets/" + d.assetName, d.file, d.size, d.crc, ts);
            }
            // 垃圾代码：junk dex 作为附加 classes(N+1).dex（真实类，干扰反编译分析）
            if (junkDex != null && junkDex.isFile()) {
                String junkName = "classes" + (origDexCount + 1) + ".dex";
                putEntry(zos, junkName, readFile(junkDex), ZipEntry.DEFLATED, ts);
                log("  垃圾代码: 已注入 " + junkName + " (" + (junkDex.length() / 1024) + " KB)");
            }
        }
    }

    private static void copyEntry(ZipFile zip, ZipOutputStream zos, ZipEntry e, boolean scrub,
                                  String overrideName) throws Exception {
        ZipEntry out = new ZipEntry(overrideName != null ? overrideName : e.getName());
        // 资源混淆：时间戳统一清零；new ZipEntry 不复制 extra，天然剥离
        out.setTime(scrub ? META_SCRUB_TIME : e.getTime());
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

    /** 读取 zip 内指定条目的全部字节；条目不存在返回 null */
    private static byte[] readZipBytes(ZipFile zip, String name) throws Exception {
        ZipEntry e = zip.getEntry(name);
        if (e == null) return null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream((int) e.getSize());
        try (InputStream in = zip.getInputStream(e)) {
            transfer(in, bos);
        }
        return bos.toByteArray();
    }

    private static void putEntry(ZipOutputStream zos, String name, byte[] data, int method, long ts)
            throws Exception {
        ZipEntry e = new ZipEntry(name);
        e.setTime(ts);
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

    /** 从文件流式写入 STORED entry（size/crc 需预知，由加密落盘时记录） */
    private static void putFileEntry(ZipOutputStream zos, String name, File f, long size, long crc,
                                     long ts) throws Exception {
        ZipEntry e = new ZipEntry(name);
        e.setTime(ts);
        e.setMethod(ZipEntry.STORED);
        e.setSize(size);
        e.setCompressedSize(size);
        e.setCrc(crc);
        zos.putNextEntry(e);
        try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
            transfer(in, zos);
        }
        zos.closeEntry();
    }

    /** DEX 载荷的落盘产物（size/crc 为密文属性，供 STORED 写入 zip） */
    private static final class EncDex {
        final File file;
        final long size;
        final long crc;
        final long origSize;
        /** 最终写入 APK 的资产名（默认名或随机名） */
        String assetName;
        /** 载荷文件 SHA-256（hex），壳加载前校验 */
        String sha256;

        EncDex(File file, long size, long crc, long origSize) {
            this.file = file;
            this.size = size;
            this.crc = crc;
            this.origSize = origSize;
        }
    }

    /** dexEncrypt 关闭时的明文落盘：流式复制 + CRC32 记录 */
    private static EncDex copyDexToFile(File apk, String dexName, File out) throws Exception {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        long origSize;
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry e = zip.getEntry(dexName);
            if (e == null) {
                throw new Exception("APK 中缺少条目 " + dexName);
            }
            origSize = e.getSize();
            try (InputStream in = new BufferedInputStream(zip.getInputStream(e));
                 java.util.zip.CheckedOutputStream cos = new java.util.zip.CheckedOutputStream(
                         new BufferedOutputStream(new FileOutputStream(out)), crc)) {
                transfer(in, cos);
            }
        }
        return new EncDex(out, out.length(), crc.getValue(), origSize);
    }

    /** 流式计算文件 SHA-256（hex 小写） */
    private static String sha256File(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
        }
        return bytesToHex(md.digest());
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    /** DEX 资产名：资产名随机化开启时随机化，否则默认名 */
    private static String dexAssetName(int i, boolean randomize, boolean dexEnc) {
        if (randomize) {
            return randomHex(8) + ".gdx";
        }
        return dexEnc ? String.format(Locale.US, DEX_ASSET_FORMAT, i)
                      : String.format(Locale.US, "glass_dex_%d.bin", i);
    }

    private static String randomHex(int len) {
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(Character.forDigit(r.nextInt(16), 16));
        }
        return sb.toString();
    }

    /**
     * 流式加密单个 DEX：ZIP 条目流 → CipherOutputStream(AES-CBC) → 落盘文件，
     * 同时用 CheckedOutputStream 记录密文 CRC32。全程 O(64KB) 内存，
     * 修复加固大 APK 时全量 byte[] 堆积导致的 OutOfMemoryError 闪退。
     */
    private static EncDex encryptDexToFile(File apk, String dexName, byte[] key, File out)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(key));
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        long origSize;
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry e = zip.getEntry(dexName);
            if (e == null) {
                throw new Exception("APK 中缺少条目 " + dexName);
            }
            origSize = e.getSize();
            try (InputStream in = new BufferedInputStream(zip.getInputStream(e));
                 java.util.zip.CheckedOutputStream cos = new java.util.zip.CheckedOutputStream(
                         new BufferedOutputStream(new FileOutputStream(out)), crc);
                 javax.crypto.CipherOutputStream cios = new javax.crypto.CipherOutputStream(cos, cipher)) {
                transfer(in, cios);
            } // cios 先关：flush padding，级联关闭 cos 与文件流
        }
        return new EncDex(out, out.length(), crc.getValue(), origSize);
    }

    // ---------------- 签名 ----------------

    private void signApk(File in, File keyStore, File out,
                         String storePass, String alias, String keyPass) throws Exception {
        // 按文件格式加载 keystore（自定义秘钥可能是 .jks/.bks/.p12/.pfx）
        KeyStore ks = KeyStore.getInstance(KeyStoreUtils.detectType(keyStore.getAbsolutePath()).getType());
        try (InputStream kin = new FileInputStream(keyStore)) {
            ks.load(kin, storePass.toCharArray());
        }
        PrivateKey key = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        java.security.cert.X509Certificate cert =
                (java.security.cert.X509Certificate) ks.getCertificate(alias);
        if (key == null || cert == null) {
            throw new Exception("keystore 中没有别名 " + alias + " 的签名密钥");
        }
        ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                alias, key, java.util.Collections.singletonList(cert)).build();
        // 直接走 apksig 库 API。不能调 ApkSignerTool.main()：CLI 失败路径会 System.exit
        // 直接杀死本加固进程（表现为加固过程中闪退、无失败提示）。
        ApkSigner signer = new ApkSigner.Builder(java.util.Collections.singletonList(signerConfig))
                .setInputApk(in)
                .setOutputApk(out)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(false)
                .build();
        signer.sign();
        if (!out.isFile() || out.length() == 0) {
            throw new Exception("签名失败：输出 APK 不存在");
        }
    }

    /** 计算 keystore 证书 SHA-256（冒号分隔大写 hex），壳运行时用它做签名校验 */
    /**
     * 目标文件已存在时追加序号：name.apk → name(1).apk → name(2).apk …
     * 避免同目录同名产物被覆盖。
     */
    private static File uniqueFile(File target) {
        if (!target.exists()) return target;
        String path = target.getAbsolutePath();
        int dot = path.lastIndexOf('.');
        String base = dot < 0 ? path : path.substring(0, dot);
        String ext = dot < 0 ? "" : path.substring(dot);
        for (int i = 1; ; i++) {
            File cand = new File(base + "(" + i + ")" + ext);
            if (!cand.exists()) return cand;
        }
    }

    private static String certSha256(File keyStore, String storePass, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStoreUtils.detectType(keyStore.getAbsolutePath()).getType());
        try (InputStream in = new FileInputStream(keyStore)) {
            ks.load(in, storePass.toCharArray());
        }
        java.security.cert.Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new Exception("keystore 中没有别名 " + alias);
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
