package com.glass.shell;

import android.app.AppComponentFactory;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;

/**
 * 壳代理 AppComponentFactory（API 28+）。
 * <p>
 * 引擎将原 manifest 的 android:appComponentFactory 改写为本类，原 factory 类名存入壳配置。
 * 时序：
 * <ol>
 *   <li>系统经本类创建壳 GlassApplication（此时原 DEX 未加载，走默认实例化）</li>
 *   <li>壳 attachBaseContext 解密原 DEX 后，实例化原 factory 并注入 {@link #origFactory}</li>
 *   <li>壳 swapApplication 触发 LoadedApk.makeApplication → 系统再次回调本类
 *       instantiateApplication(原 App 类) → 此时委托原 factory（保留其初始化逻辑，
 *       如 LSPatch/Xposed 桥注入），再返回原 App 实例</li>
 *   <li>后续 Activity/Service/Provider/Receiver 实例化均委托原 factory</li>
 * </ol>
 * 注意：instantiateClassLoader 在原 DEX 加载前由系统调用（f== 走默认），原 factory
 * 若重写该方法则该 hook 丢失，其余 hook 全保留。
 */
public class GlassAppComponentFactory extends AppComponentFactory {

    /** 原 APK 的 AppComponentFactory 实例，由 GlassApplication 在原 DEX 加载后注入 */
    static volatile AppComponentFactory origFactory;

    static void setOrigFactory(AppComponentFactory f) {
        origFactory = f;
    }

    @Override
    public android.app.Application instantiateApplication(ClassLoader cl, String className) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory f = origFactory;
        if (f != null) {
            // 原 DEX 已加载，className 为原 App 类 → 委托原 factory 创建（保留其注入逻辑）
            try {
                return f.instantiateApplication(cl, className);
            } catch (Throwable t) {
                android.util.Log.w("GlassShell", "orig factory instantiateApplication failed, fallback", t);
            }
        }
        // className 为壳 GlassApplication（启动阶段）或原 factory 缺失 → 默认实例化
        return super.instantiateApplication(cl, className);
    }

    @Override
    public android.app.Activity instantiateActivity(ClassLoader cl, String className, Intent intent) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory f = origFactory;
        if (f != null) {
            try {
                return f.instantiateActivity(cl, className, intent);
            } catch (Throwable ignored) {
            }
        }
        return super.instantiateActivity(cl, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory f = origFactory;
        if (f != null) {
            try {
                return f.instantiateReceiver(cl, className, intent);
            } catch (Throwable ignored) {
            }
        }
        return super.instantiateReceiver(cl, className, intent);
    }

    @Override
    public android.app.Service instantiateService(ClassLoader cl, String className, Intent intent) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory f = origFactory;
        if (f != null) {
            try {
                return f.instantiateService(cl, className, intent);
            } catch (Throwable ignored) {
            }
        }
        return super.instantiateService(cl, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory f = origFactory;
        if (f != null) {
            try {
                return f.instantiateProvider(cl, className);
            } catch (Throwable ignored) {
            }
        }
        return super.instantiateProvider(cl, className);
    }

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader cl, android.content.pm.ApplicationInfo appInfo) {
        // 启动阶段（原 DEX 未加载）f==null 走默认；f 已注入则委托
        AppComponentFactory f = origFactory;
        if (f != null) {
            try {
                return f.instantiateClassLoader(cl, appInfo);
            } catch (Throwable ignored) {
            }
        }
        return super.instantiateClassLoader(cl, appInfo);
    }
}
