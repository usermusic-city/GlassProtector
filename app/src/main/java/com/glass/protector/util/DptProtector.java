package com.glass.protector.util;

import android.content.Context;
import android.content.res.AssetManager;

import com.glass.protector.service.ProtectConfig;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import dalvik.system.DexClassLoader;

/**
 * DPT 引擎适配器 —— 真实现。
 * <p>
 * 原版 dpt-shell 是 PC 命令行工具（JVM）。本类把它搬到 Android 上运行：
 * 1. 释放内置的 dpt processor（dex 形式）与 shell-files 到私有目录
 * 2. DexClassLoader 加载 dpt 的全部 dex
 * 3. 反射注入 Android 环境适配参数（魔改后的 OVERRIDE_BASE_DIR / OVERRIDE_USER_DIR）
 * 4. 生成 protect-config（签名 keystore 指向内置 PKCS12）
 * 5. 调用 com.luoye.dpt.Dpt#main 执行真实加固（方法抽取 + 壳 + native 防护）
 * 6. 捕获 dpt 的 stdout 输出到日志列表
 */
public class DptProtector {

    private static final String ASSET_ROOT = "dpt_engine";
    private static final String KEYSTORE_ASSET = "glass.p12";
    private static final String KEYSTORE_PASSWORD = "glass123";
    private static final String KEYSTORE_ALIAS = "glass";

    private final ProtectConfig config;
    private final List<String> logs = new ArrayList<>();
    private final Context appContext;

    public DptProtector(ProtectConfig config) {
        this.config = config;
        this.appContext = com.glass.protector.AppContextHolder.get();
    }

    public List<String> getLogs() {
        return logs;
    }

    private void log(String msg) {
        synchronized (logs) {
            logs.add(msg);
        }
    }

    public String protect() throws Exception {
        logs.clear();
        log("=== DPT 引擎（函数抽取壳，原版 dpt-shell） ===");
        log("输入: " + config.getInputApkPath());

        if (appContext == null) {
            throw new Exception("Application context 不可用");
        }
        File input = new File(config.getInputApkPath());
        if (!input.isFile()) {
            throw new Exception("输入 APK 不存在: " + input);
        }
        String outDir = config.getOutputDir();
        ApkUtils.ensureDir(outDir);
        String workDir = outDir + "/dpt_work_" + System.currentTimeMillis();
        ApkUtils.ensureDir(workDir);

        // 1. 释放 dpt engine 运行资源（shell-files + keystore；引擎 dex 不走 assets）
        log("[1/6] 释放 DPT 引擎运行时 ...");
        File engineDir = new File(appContext.getFilesDir(), "dpt_engine");
        deleteRecursive(engineDir);
        ApkUtils.ensureDir(engineDir.getAbsolutePath());
        extractAssets(ASSET_ROOT, engineDir);
        File shellFiles = new File(engineDir, "shell-files");
        if (!new File(shellFiles, "dex").isDirectory()) {
            throw new Exception("shell-files 缺失（assets/" + ASSET_ROOT + "/shell-files），请使用 CI 构建的完整版本");
        }
        log("  引擎文件释放完成: " + engineDir.getAbsolutePath());

        // 2. Android 环境注入：tmpdir（Const.ROOT_OF_OUT_DIR 静态读取）
        System.setProperty("java.io.tmpdir", workDir);

        // 3. 加载 dpt processor。
        //    引擎 dex 以 libdptcore*.so（伪装 .so）形式打进 jniLibs，安装时由系统
        //    解压到 nativeLibraryDir（app 只读），规避 Android 8.0+ 的
        //    "Writable dex file not allowed" 限制（files/cache 目录禁止加载 dex）。
        log("[2/6] 加载 DPT processor ...");
        String nativeDir = appContext.getApplicationInfo().nativeLibraryDir;
        File[] soDexes = new File(nativeDir).listFiles(
                (dir, name) -> name.startsWith("libdptcore") && name.endsWith(".so"));
        if (soDexes == null || soDexes.length == 0) {
            throw new Exception("DPT 引擎 dex 未安装到 nativeLibraryDir（" + nativeDir
                    + "），请卸载后重新安装 CI 构建的完整版本");
        }
        Arrays.sort(soDexes);
        StringBuilder dexPaths = new StringBuilder();
        for (File f : soDexes) {
            if (dexPaths.length() > 0) dexPaths.append(File.pathSeparatorChar);
            dexPaths.append(f.getAbsolutePath());
        }
        log("  引擎 dex: " + dexPaths);
        File odexDir = new File(appContext.getCacheDir(), "dpt_odex");
        ApkUtils.ensureDir(odexDir.getAbsolutePath());
        ClassLoader parent = DptProtector.class.getClassLoader();
        DexClassLoader dexCl = new DexClassLoader(dexPaths.toString(),
                odexDir.getAbsolutePath(), null, parent);

        // 4. 反射注入环境参数
        log("[3/6] 注入 Android 运行环境 ...");
        Class<?> futils = Class.forName("com.luoye.dpt.util.FileUtils", true, dexCl);
        futils.getField("OVERRIDE_BASE_DIR").set(null, engineDir.getAbsolutePath());
        futils.getField("OVERRIDE_USER_DIR").set(null, outDir);

        // 5. protect-config（签名走内置 PKCS12，Android 不支持原版 JKS）
        log("[4/6] 生成 protect-config ...");
        File keyStore = new File(engineDir, KEYSTORE_ASSET);
        if (!keyStore.isFile()) {
            keyStore = extractAssetTop(KEYSTORE_ASSET, new File(engineDir, KEYSTORE_ASSET));
        }
        File cfgFile = new File(workDir, "protect-config.json");
        writeBytes(cfgFile, ("{\"signature\":{\"keystore\":" + jsonStr(keyStore.getAbsolutePath())
                + ",\"alias\":" + jsonStr(KEYSTORE_ALIAS)
                + ",\"storepass\":" + jsonStr(KEYSTORE_PASSWORD)
                + ",\"keypass\":" + jsonStr(KEYSTORE_PASSWORD) + "}}")
                .getBytes(StandardCharsets.UTF_8));

        // 6. 调用 Dpt.main
        log("[5/6] 执行 DPT 加固（方法抽取 + 壳化 + native 防护）...");
        List<String> args = new ArrayList<>();
        args.add("-f");
        args.add(input.getAbsolutePath());
        args.add("-o");
        args.add(outDir);
        args.add("-c");
        args.add(cfgFile.getAbsolutePath());
        if (config.isDptSignVerify()) {
            args.add("--vs");
        }
        if (!config.isDptAntiDebug()) {
            args.add("--disable-anti-debug");
        }
        if (!config.isDptJunkCode()) {
            // 原版 junkcode 无 CLI 开关，由 shell-files 决定；此处保留参数占位
        }
        args.add("--noisy-log");

        Class<?> dptClass = Class.forName("com.luoye.dpt.Dpt", true, dexCl);
        PrintStream oldOut = System.out;
        PrintStream oldErr = System.err;
        System.setOut(new LogPrintStream(oldOut));
        System.setErr(new LogPrintStream(oldErr));
        try {
            dptClass.getMethod("main", String[].class)
                    .invoke(null, (Object) args.toArray(new String[0]));
        } finally {
            System.setOut(oldOut);
            System.setErr(oldErr);
        }

        // 7. 校验输出（Dpt.main 吞异常，只能靠产物判断成败）
        log("[6/6] 校验输出 ...");
        String signedName = input.getName().replaceAll("\\.apk$", "") + "_signed.apk";
        File outApk = new File(outDir, signedName);
        if (!outApk.isFile() || outApk.length() == 0) {
            // 找不到 _signed 就扫目录里最新的 apk
            File fallback = findNewestApk(new File(outDir), input.getName());
            if (fallback != null) {
                outApk = fallback;
            } else {
                throw new Exception("DPT 加固失败：未生成输出文件（详见上方引擎日志）");
            }
        }
        deleteRecursive(new File(workDir));
        log("=== DPT 加固完成: " + outApk.getAbsolutePath() + " ===");
        return outApk.getAbsolutePath();
    }

    // ---------------- assets 释放 ----------------

    private void extractAssets(String assetDir, File destDir) throws Exception {
        AssetManager am = appContext.getAssets();
        String[] children = am.list(assetDir);
        if (children == null || children.length == 0) {
            throw new Exception("assets/" + assetDir + " 为空，请使用 CI 构建的完整版本");
        }
        for (String name : children) {
            String assetPath = assetDir + "/" + name;
            String[] sub = am.list(assetPath);
            if (sub != null && sub.length > 0) {
                File subDir = new File(destDir, name);
                ApkUtils.ensureDir(subDir.getAbsolutePath());
                extractAssets(assetPath, subDir);
            } else {
                File out = new File(destDir, name);
                try (InputStream in = am.open(assetPath)) {
                    writeBytes(out, readAll(in));
                }
            }
        }
    }

    private File extractAssetTop(String assetName, File dest) throws Exception {
        try (InputStream in = appContext.getAssets().open(assetName)) {
            writeBytes(dest, readAll(in));
        }
        return dest;
    }

    // ---------------- stdout 捕获 ----------------

    /** 把 dpt 引擎的 stdout/stderr 实时转进日志列表 */
    private class LogPrintStream extends PrintStream {
        private final PrintStream mirror;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        LogPrintStream(PrintStream mirror) {
            super(new ByteArrayOutputStream(), true);
            this.mirror = mirror;
        }

        @Override
        public void write(int b) {
            mirror.write(b);
            buf.write(b);
            if (b == '\n') {
                flushLine();
            }
        }

        @Override
        public void write(byte[] b, int off, int len) {
            mirror.write(b, off, len);
            for (int i = 0; i < len; i++) {
                buf.write(b[off + i]);
                if (b[off + i] == '\n') {
                    flushLine();
                }
            }
        }

        private void flushLine() {
            byte[] data = buf.toByteArray();
            buf.reset();
            if (data.length == 0) return;
            // 去掉行尾 \r\n
            int end = data.length;
            if (end > 0 && data[end - 1] == '\n') end--;
            if (end > 0 && data[end - 1] == '\r') end--;
            String line = new String(data, 0, end, StandardCharsets.UTF_8);
            if (!line.trim().isEmpty()) {
                log(line);
            }
        }
    }

    // ---------------- 工具 ----------------

    private static String jsonStr(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static List<File> listFilesRecursive(File dir, String suffix) {
        List<File> out = new ArrayList<>();
        File[] children = dir.listFiles();
        if (children == null) return out;
        for (File c : children) {
            if (c.isDirectory()) {
                out.addAll(listFilesRecursive(c, suffix));
            } else if (c.getName().endsWith(suffix)) {
                out.add(c);
            }
        }
        return out;
    }

    private static File findNewestApk(File dir, String excludeName) {
        File newest = null;
        File[] children = dir.listFiles();
        if (children == null) return null;
        for (File c : children) {
            if (c.isFile() && c.getName().endsWith(".apk")
                    && !c.getName().equals(excludeName)
                    // 签名失败时 DPT 会留下 unsigned_/unzipalign_ 中间包，不能当成功产物
                    && !c.getName().startsWith("unsigned_")
                    && !c.getName().startsWith("unzipalign_")
                    && !c.getName().startsWith("temp_")
                    && (newest == null || c.lastModified() > newest.lastModified())) {
                newest = c;
            }
        }
        return newest;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    private static void writeBytes(File f, byte[] data) throws Exception {
        try (OutputStream os = new FileOutputStream(f)) {
            os.write(data);
        }
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
