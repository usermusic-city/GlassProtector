package com.glass.shell;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Debug;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * 运行时反篡改检测。
 * 任一检测命中即静默自杀（不弹提示，避免给攻击者反馈）。
 */
final class AntiTamper {

    private AntiTamper() {
    }

    static void check(Context ctx, ShellData cfg) {
        try {
            if (cfg.antiDebug) {
                checkDebugger();
            }
            if (cfg.antiFrida) {
                checkFrida();
            }
            if (cfg.signSha256 != null && cfg.signSha256.length() > 0) {
                checkSignature(ctx, cfg.signSha256);
            }
        } catch (Throwable ignored) {
            // 检测自身异常不阻断启动
        }
    }

    private static void die() {
        android.os.Process.killProcess(android.os.Process.myPid());
        System.exit(0);
    }

    /** 反调试：TracerPid + JDWP 标志 */
    private static void checkDebugger() {
        try {
            File status = new File("/proc/self/status");
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(status), StandardCharsets.UTF_8));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String pid = line.substring(10).trim();
                    if (!pid.equals("0")) {
                        die();
                    }
                    break;
                }
            }
            r.close();
        } catch (Throwable ignored) {
        }
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            die();
        }
    }

    /** Frida 检测：so 名特征 + 默认端口 */
    private static void checkFrida() {
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream("/proc/self/maps"), StandardCharsets.UTF_8));
            String line;
            while ((line = r.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") || lower.contains("gum-js-loop") || lower.contains("gmain")) {
                    r.close();
                    die();
                }
            }
            r.close();
        } catch (Throwable ignored) {
        }
        // frida-server 默认端口
        try {
            java.net.Socket s = new java.net.Socket();
            s.connect(new java.net.InetSocketAddress("127.0.0.1", 27042), 200);
            s.close();
            die();
        } catch (Throwable ignored) {
        }
    }

    /** 签名校验：当前 APK 签名 SHA-256 必须与加固时一致 */
    static void checkSignature(Context ctx, String expectedHex) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            android.content.pm.Signature[] sigs = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures;
            if (sigs == null || sigs.length == 0) {
                die();
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(sigs[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", digest[i]));
            }
            if (!sb.toString().equalsIgnoreCase(expectedHex)) {
                die();
            }
        } catch (Throwable t) {
            // PackageManager 异常视为校验失败
            die();
        }
    }
}
