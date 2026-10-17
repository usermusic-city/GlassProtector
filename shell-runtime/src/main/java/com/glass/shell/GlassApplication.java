package com.glass.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Glass 壳入口。加固引擎把原 APK 的 Application 类名改成本类，
 * 原 Application 与全部业务 DEX 被加密进 assets（或明文保留，视配置）。
 * <p>
 * 启动流程：
 * 1. attachBaseContext：读配置（Dex2C 时优先 native ELF 容器）→ 反篡改检测
 *    → 逐个 SHA-256 完整性校验 → 解密 DEX（明文模式直读）→ 注入宿主 ClassLoader → 替换回原 Application
 * 2. onCreate：回调原 Application 的 onCreate
 */
public class GlassApplication extends Application {

    private Application realApp;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            bootstrap(base);
        } catch (Throwable t) {
            // 壳启动失败是最严重的故障：保留崩溃日志线索后终止
            android.util.Log.e("GlassShell", "bootstrap failed", t);
            throw new RuntimeException("glass shell bootstrap failed", t);
        }
    }

    private void bootstrap(Context base) throws Exception {
        // 1. 读配置（Dex2C 模式优先从 nativeLibraryDir/libglass_core.so 提取）
        ShellData cfg = ShellData.load(base);
        if (cfg.fromElf) {
            android.util.Log.i("GlassShell", "config loaded from native ELF container");
        }

        // 2. 反篡改（命中即自杀，不返回）
        AntiTamper.check(base, cfg);

        // 3. 逐个校验并解密 DEX（明文模式直读）
        byte[][] dexes = new byte[cfg.dexCount][];
        for (int i = 0; i < cfg.dexCount; i++) {
            String assetName = cfg.assetName(i);
            byte[] enc = ShellData.readAsset(base.getAssets(), assetName);
            // 完整性校验：载荷被篡改/替换时拒绝启动
            String expect = cfg.expectedSha(i);
            if (expect != null) {
                String actual = sha256Hex(enc);
                if (!expect.equalsIgnoreCase(actual)) {
                    throw new SecurityException("dex payload integrity check failed: "
                            + assetName);
                }
            }
            if (cfg.dexEnc) {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cfg.aesKey, "AES"),
                        new IvParameterSpec(cfg.aesIv));
                dexes[i] = cipher.doFinal(enc);
            } else {
                dexes[i] = enc;
            }
        }

        // 4. 加载解密后的 DEX
        ClassLoader host = GlassApplication.class.getClassLoader();
        ClassLoader loader = createLoader(base, dexes, host);

        // 5. 注入宿主 ClassLoader
        DexInjector.inject(host, loader);

        // 5.5 原 appComponentFactory 接管（API 28+，失败降级默认实例化）
        setupOrigFactory(loader, cfg);

        // 6. 替换回原 Application
        swapApplication(cfg.origApplication);
    }

    /**
     * 实例化原 APK 的 AppComponentFactory 并注入壳代理工厂。
     * 必须在 swapApplication 之前完成：LoadedApk.makeApplication（API 28+）会经
     * 壳 factory 回调 instantiateApplication(原 App 类)，此时委托原 factory
     * 以保留其初始化逻辑（如 LSPatch/Xposed 桥注入）。
     */
    private void setupOrigFactory(ClassLoader loader, ShellData cfg) {
        String name = cfg.origFactory;
        if (name == null || name.isEmpty()) {
            return;
        }
        try {
            Class<?> fc = loader.loadClass(name);
            Object inst = fc.getDeclaredConstructor().newInstance();
            if (inst instanceof android.app.AppComponentFactory) {
                GlassAppComponentFactory.setOrigFactory((android.app.AppComponentFactory) inst);
                android.util.Log.i("GlassShell", "orig appComponentFactory proxied: " + name);
            } else {
                android.util.Log.w("GlassShell", "orig factory not AppComponentFactory: " + name);
            }
        } catch (Throwable t) {
            // 原 factory 初始化失败：降级为默认实例化，不阻断启动
            android.util.Log.w("GlassShell", "orig factory init failed, fallback to default", t);
        }
    }

    private static String sha256Hex(byte[] data) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(data);
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte x : d) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private ClassLoader createLoader(Context base, byte[][] dexes, ClassLoader host) throws Exception {
        if (Build.VERSION.SDK_INT >= 26) {
            // O+ 直接内存加载，不落盘
            ByteBuffer[] bufs = new ByteBuffer[dexes.length];
            for (int i = 0; i < dexes.length; i++) {
                bufs[i] = ByteBuffer.wrap(dexes[i]);
            }
            return new dalvik.system.InMemoryDexClassLoader(bufs, host);
        } else {
            // N/Nougat：写私有目录再加载
            File dir = new File(base.getCacheDir(), "gd");
            if (!dir.exists() && !dir.mkdirs()) {
                throw new IllegalStateException("cannot create dex cache dir");
            }
            StringBuilder paths = new StringBuilder();
            for (int i = 0; i < dexes.length; i++) {
                File f = new File(dir, "gd_" + i + ".dex");
                FileOutputStream fos = new FileOutputStream(f);
                fos.write(dexes[i]);
                fos.close();
                if (paths.length() > 0) paths.append(File.pathSeparatorChar);
                paths.append(f.getAbsolutePath());
            }
            return new dalvik.system.DexClassLoader(paths.toString(), dir.getAbsolutePath(),
                    base.getApplicationInfo().nativeLibraryDir, host);
        }
    }

    /**
     * 经典 Application 替换流程：
     * LoadedApk.mApplication = null → makeApplication(false)（内部创建原 App 并 attach）
     * → ActivityThread.mInitialApplication / mAllApplications 更新
     * → ContextImpl.mOuterContext 更新
     */
    private void swapApplication(String origApp) throws Exception {
        if (origApp == null || origApp.isEmpty()
                || Application.class.getName().equals(origApp)) {
            // 原 APK 无自定义 Application，无需替换
            return;
        }
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Method current = atClass.getDeclaredMethod("currentActivityThread");
        current.setAccessible(true);
        Object activityThread = current.invoke(null);

        Object boundApp = DexInjector.getField(activityThread, "mBoundApplication");
        Object loadedApk = DexInjector.getField(boundApp, "info");
        Object appInfoObj = DexInjector.getField(loadedApk, "mApplicationInfo");

        // 指向原 Application
        if (appInfoObj instanceof ApplicationInfo) {
            ((ApplicationInfo) appInfoObj).className = origApp;
        }
        DexInjector.setField(loadedApk, "mApplication", null);

        // makeApplication(false, null)：创建原 App 实例并 attach，不触发 onCreate
        realApp = (Application) DexInjector.call(loadedApk, "makeApplication",
                new Class<?>[]{boolean.class, android.app.Instrumentation.class}, false, null);

        // ActivityThread.mInitialApplication
        DexInjector.setField(activityThread, "mInitialApplication", realApp);

        // mAllApplications 更新
        @SuppressWarnings("unchecked")
        ArrayList<Application> allApps = (ArrayList<Application>) DexInjector.getField(activityThread, "mAllApplications");
        if (allApps != null) {
            allApps.remove(this);
            if (!allApps.contains(realApp)) {
                allApps.add(realApp);
            }
        }

        // ContextImpl.mOuterContext（让 getApplicationContext() 返回原 App）
        try {
            Object baseCtx = getBaseContext();
            DexInjector.setField(baseCtx, "mOuterContext", realApp);
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (realApp != null) {
            try {
                Class<?> atClass = Class.forName("android.app.ActivityThread");
                Method current = atClass.getDeclaredMethod("currentActivityThread");
                current.setAccessible(true);
                Object activityThread = current.invoke(null);
                Object instrument = DexInjector.getField(activityThread, "mInstrumentation");
                DexInjector.call(instrument, "callApplicationOnCreate",
                        new Class<?>[]{Application.class}, realApp);
            } catch (Throwable t) {
                android.util.Log.e("GlassShell", "forward onCreate failed", t);
            }
        }
    }
}
