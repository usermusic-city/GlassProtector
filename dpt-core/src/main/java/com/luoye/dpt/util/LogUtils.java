package com.luoye.dpt.util;

/**
 * 日志工具类 - 从dpt-shell移植
 */
public class LogUtils {

    private static boolean noisyLog = false;
    private static final String TAG = "dpt";

    public static void setNoisyLog(boolean noisy) {
        noisyLog = noisy;
    }

    public static void info(String msg) {
        System.out.println("[INFO] " + msg);
    }

    public static void warn(String msg) {
        System.out.println("[WARN] " + msg);
    }

    public static void error(String msg) {
        System.err.println("[ERROR] " + msg);
    }

    public static void error(String msg, Throwable t) {
        System.err.println("[ERROR] " + msg);
        t.printStackTrace();
    }

    public static void verbose(String msg) {
        if (noisyLog) {
            System.out.println("[VERBOSE] " + msg);
        }
    }

    public static void debug(String msg) {
        if (noisyLog) {
            System.out.println("[DEBUG] " + msg);
        }
    }
}
