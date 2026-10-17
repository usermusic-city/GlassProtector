#!/usr/bin/env python3
"""
dpt-shell Android 运行时适配补丁。

GlassProtector 的 DPT 引擎在 Android 上通过 DexClassLoader 加载 dpt 的 dex 运行，
原版 dpt 是为 PC JVM 设计的，有 4 处环境依赖必须适配：

1. FileUtils.getExecutablePath(): PC 上取 jar 所在目录；Android 上 getProtectionDomain
   不可用 → 加静态字段 OVERRIDE_BASE_DIR，外部注入 baseDir（shell-files 所在目录）
2. FileUtils.getUserDir(): PC 上 System.getProperty("user.dir")；Android 返回 "/"
   → 加静态字段 OVERRIDE_USER_DIR
3. Const.ROOT_OF_OUT_DIR: Android 上 java.io.tmpdir 为 null → 加 fallback，
   外部通过 System.setProperty("java.io.tmpdir", ...) 注入工作目录
4. ZipUtils.readResourceFromRuntime: Android 的 DexClassLoader 无法读 jar 内资源
   → inputStream 为 null 时 fallback 从 baseDir 下读文件

所有替换都是精确字符串匹配，找不到目标直接报错退出（防止上游更新后静默失效）。
"""
import sys


def patch_file(path, replacements):
    with open(path, encoding='utf-8') as f:
        content = f.read()
    for old, new in replacements:
        if old not in content:
            print(f"PATCH FAILED: pattern not found in {path}:\n---\n{old}\n---")
            sys.exit(1)
        if content.count(old) != 1:
            print(f"PATCH FAILED: pattern appears {content.count(old)} times in {path}")
            sys.exit(1)
        content = content.replace(old, new)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"patched: {path}")


def main(dpt_root):
    futils = dpt_root + '/dpt/src/main/java/com/luoye/dpt/util/FileUtils.java'
    patch_file(futils, [
        # 1. getExecutablePath 注入点
        (
            '    public static String getExecutablePath() {\n        try {',
            '    public static String OVERRIDE_BASE_DIR = null;\n'
            '    public static String OVERRIDE_USER_DIR = null;\n\n'
            '    public static String getExecutablePath() {\n'
            '        if (OVERRIDE_BASE_DIR != null) {\n'
            '            return OVERRIDE_BASE_DIR;\n'
            '        }\n'
            '        try {'
        ),
        # 2. getUserDir 注入点
        (
            '    public static String getUserDir() {\n        return System.getProperty("user.dir");',
            '    public static String getUserDir() {\n'
            '        if (OVERRIDE_USER_DIR != null) {\n'
            '            return OVERRIDE_USER_DIR;\n'
            '        }\n'
            '        return System.getProperty("user.dir");'
        ),
    ])

    const = dpt_root + '/dpt/src/main/java/com/luoye/dpt/config/Const.java'
    patch_file(const, [
        # 3. tmpdir null fallback
        (
            '    public static final String ROOT_OF_OUT_DIR = System.getProperty("java.io.tmpdir");',
            '    public static final String ROOT_OF_OUT_DIR = System.getProperty("java.io.tmpdir") == null'
            ' ? "/data/local/tmp" : System.getProperty("java.io.tmpdir");'
        ),
    ])

    zutils = dpt_root + '/dpt/src/main/java/com/luoye/dpt/util/ZipUtils.java'
    patch_file(zutils, [
        # 4. 资源读取文件 fallback（Android DexClassLoader 读不到 jar 内资源）
        (
            '        if (inputStream == null) {\n'
            '            throw new IOException("cannot get resource:" + resourcePath);\n'
            '        }',
            '        if (inputStream == null) {\n'
            '            // Android: fallback to plain file under executable path\n'
            '            java.io.File fallbackFile = new java.io.File(\n'
            '                    com.luoye.dpt.util.FileUtils.getExecutablePath(), resourcePath);\n'
            '            if (fallbackFile.isFile()) {\n'
            '                inputStream = new java.io.FileInputStream(fallbackFile);\n'
            '            }\n'
            '        }\n'
            '        if (inputStream == null) {\n'
            '            throw new IOException("cannot get resource:" + resourcePath);\n'
            '        }'
        ),
    ])

    # ---------- 5. 签名走 apksig 库 API（Android 上 CLI 入口 System.exit 杀宿主进程） ----------
    # ApkSignerTool.main() 末尾 System.exit(run(params))：签名成功 exit(0)、失败 exit(1)，
    # 两者都会直接杀死 Android 宿主进程（表现为加固中 app 突然消失、回到加固页、无产物）。
    # 与 GlassProtectorEngine.signApk 同款方案：ApkSigner.Builder 库 API 直接签名。
    apk_java = dpt_root + '/dpt/src/main/java/com/luoye/dpt/builder/Apk.java'
    patch_file(apk_java, [
        (
            '        int size = commandList.size();\n'
            '        String[] commandArray = new String[size];\n'
            '        commandArray = commandList.toArray(commandArray);\n'
            '\n'
            '        try {\n'
            '            ApkSignerTool.main(commandArray);\n'
            '        } catch (Exception e) {\n'
            '            e.printStackTrace();\n'
            '            return false;\n'
            '        }\n'
            '        return true;\n'
            '    }',
            '        try {\n'
            '            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");\n'
            '            try (java.io.FileInputStream fin = new java.io.FileInputStream(keyStorePath)) {\n'
            '                ks.load(fin, storePassword.toCharArray());\n'
            '            }\n'
            '            java.security.PrivateKey privateKey =\n'
            '                    (java.security.PrivateKey) ks.getKey(keyAlias, KeyPassword.toCharArray());\n'
            '            java.security.cert.X509Certificate cert =\n'
            '                    (java.security.cert.X509Certificate) ks.getCertificate(keyAlias);\n'
            '            if (privateKey == null || cert == null) {\n'
            '                LogUtils.error("Sign fail: no key/cert for alias " + keyAlias);\n'
            '                return false;\n'
            '            }\n'
            '            com.android.apksig.ApkSigner.SignerConfig signerConfig =\n'
            '                    new com.android.apksig.ApkSigner.SignerConfig.Builder(\n'
            '                            keyAlias, privateKey,\n'
            '                            java.util.Collections.singletonList(cert)).build();\n'
            '            com.android.apksig.ApkSigner signer =\n'
            '                    new com.android.apksig.ApkSigner.Builder(\n'
            '                            java.util.Collections.singletonList(signerConfig))\n'
            '                            .setInputApk(new java.io.File(packagePath))\n'
            '                            .setOutputApk(new java.io.File(signedPackagePath))\n'
            '                            .setV1SigningEnabled(true)\n'
            '                            .setV2SigningEnabled(true)\n'
            '                            .setV3SigningEnabled(true)\n'
            '                            .build();\n'
            '            signer.sign();\n'
            '            return true;\n'
            '        } catch (Throwable t) {\n'
            '            t.printStackTrace();\n'
            '            return false;\n'
            '        }\n'
            '    }'
        ),
    ])

    # ---------- Java 9+ API 降级为 Java 8（d8 --min-api 24 无法 desugar 库 API） ----------
    dpt_main = dpt_root + '/dpt/src/main/java/com/luoye/dpt/Dpt.java'
    patch_file(dpt_main, [
        (
            'String value = Files.readString(keyFile.toPath(), StandardCharsets.UTF_8).trim();',
            'String value = new String(Files.readAllBytes(keyFile.toPath()), StandardCharsets.UTF_8).trim();'
        ),
    ])

    aab = dpt_root + '/dpt/src/main/java/com/luoye/dpt/builder/Aab.java'
    patch_file(aab, [
        (
            '                // Drain stdout/stderr to avoid pipe buffer deadlock\n'
            '                inputStream.readAllBytes();',
            '                // Drain stdout/stderr to avoid pipe buffer deadlock\n'
            '                byte[] drainBuf = new byte[8192];\n'
            '                while (inputStream.read(drainBuf) > 0) { }'
        ),
    ])

    rci = dpt_root + '/dpt/src/main/java/com/luoye/dpt/dex/ReflectionClinitInjector.java'
    patch_file(rci, [
        (
            '    private static final Set<String> SKIPPED_CLASS_TYPES = Set.of(\n'
            '            "Landroidx/multidex/MultiDex;",\n'
            '            "Lcom/android/support/multidex/MultiDex;"\n'
            '    );',
            '    private static final Set<String> SKIPPED_CLASS_TYPES = new java.util.HashSet<>(\n'
            '            java.util.Arrays.asList(\n'
            '            "Landroidx/multidex/MultiDex;",\n'
            '            "Lcom/android/support/multidex/MultiDex;"\n'
            '    ));'
        ),
        (
            '                        List.of("Ljava/lang/String;", CLASS_ARRAY),',
            '                        java.util.Arrays.asList("Ljava/lang/String;", CLASS_ARRAY),'
        ),
        (
            '                        List.of("Ljava/lang/Object;", OBJECT_ARRAY),',
            '                        java.util.Arrays.asList("Ljava/lang/Object;", OBJECT_ARRAY),'
        ),
    ])
    print("ALL DPT PATCHES APPLIED")


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
