package com.glass.protector;

import android.content.Context;

/**
 * 全局 Application Context 持有者。
 * 加固引擎需要用它释放内置 assets（shell.dex / glass.p12）。
 */
public final class AppContextHolder {

    private static Context sAppContext;

    private AppContextHolder() {
    }

    static void init(Context context) {
        sAppContext = context.getApplicationContext();
    }

    public static Context get() {
        return sAppContext;
    }
}
