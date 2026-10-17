package com.glass.protector.service;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.SystemClock;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.glass.protector.GlassApp;
import com.glass.protector.MainActivity;
import com.glass.protector.R;
import com.glass.protector.util.GlassProtectorEngine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

/**
 * 加固前台服务 - 在后台真实执行APK加固处理。
 * 通过静态内部类 {@link ProtectState} 向结果页暴露实时进度。
 */
public class ProtectService extends Service {

    public static final String EXTRA_CONFIG = "protect_config";
    private static final int NOTIFICATION_ID = 1001;

    private ProtectConfig config;
    private volatile boolean isRunning = false;

    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.hasExtra(EXTRA_CONFIG)) {
            config = (ProtectConfig) intent.getSerializableExtra(EXTRA_CONFIG);
        }

        if (config == null) {
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, buildNotification("正在准备加固..."));

        // 在后台线程执行加固
        new Thread(this::executeProtect, "protect-worker").start();

        return START_NOT_STICKY;
    }

    private void executeProtect() {
        isRunning = true;
        ProtectState.begin(config);
        long start = SystemClock.elapsedRealtime();
        updateNotification("正在初始化加固引擎...");

        try {
            GlassProtectorEngine engine = new GlassProtectorEngine(config);
            String output = runWithLogPump(engine::getLogs, engine::protect);

            ProtectState.elapsedMs = SystemClock.elapsedRealtime() - start;
            ProtectState.finishSuccess(output);
            updateNotification("加固完成");
        } catch (Throwable t) {
            // 必须接 Throwable：OutOfMemoryError 等 Error 不是 Exception，
            // 漏接会导致加固线程崩溃直接杀死进程（表现为加固中闪退）
            ProtectState.elapsedMs = SystemClock.elapsedRealtime() - start;
            ProtectState.finishFailure(t);
            updateNotification("加固失败: " + ProtectState.errorMsg);
        } finally {
            isRunning = false;
            stopSelf();
        }
    }

    /**
     * 执行 protect() 的同时启动日志泵线程，把引擎日志实时同步到 ProtectState。
     */
    private String runWithLogPump(Supplier<List<String>> logsSupplier,
                                  ThrowingSupplier<String> protectAction) throws Exception {
        Thread pump = new Thread(() -> {
            int idx = 0;
            while (ProtectState.status == ProtectState.STATUS_RUNNING) {
                List<String> all = logsSupplier.get();
                while (idx < all.size()) {
                    String line = all.get(idx++);
                    ProtectState.appendLog(line);
                    updateNotification(line);
                }
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    break;
                }
            }
            // 最终flush，确保protect()末尾产生的日志不丢失
            List<String> all = logsSupplier.get();
            while (idx < all.size()) {
                ProtectState.appendLog(all.get(idx++));
            }
        }, "log-pump");
        pump.setDaemon(true);
        pump.start();

        try {
            return protectAction.get();
        } finally {
            try {
                pump.join(1000);
            } catch (InterruptedException ignored) {
            }
        }
    }

    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    // ==================== 供结果页订阅的静态状态 ====================

    public static final class ProtectState {
        public static final int STATUS_IDLE = 0;
        public static final int STATUS_RUNNING = 1;
        public static final int STATUS_SUCCESS = 2;
        public static final int STATUS_FAILED = 3;

        public static volatile int status = STATUS_IDLE;
        public static volatile String outputPath = null;
        public static volatile String errorMsg = null;
        public static volatile long elapsedMs = 0;

        private static final List<String> logs =
                Collections.synchronizedList(new ArrayList<>());

        private static void begin(ProtectConfig cfg) {
            synchronized (logs) {
                logs.clear();
            }
            status = STATUS_RUNNING;
            outputPath = null;
            errorMsg = null;
            elapsedMs = 0;
            appendLog("[*] 加固任务已启动，引擎: Glass");
        }

        public static void appendLog(String line) {
            if (line == null || line.isEmpty()) return;
            synchronized (logs) {
                logs.add(line);
            }
        }

        public static List<String> snapshotLogs() {
            synchronized (logs) {
                return new ArrayList<>(logs);
            }
        }

        private static void finishSuccess(String path) {
            outputPath = path;
            status = STATUS_SUCCESS;
        }

        private static void finishFailure(Throwable t) {
            errorMsg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
            appendLog("[!] 加固失败: " + errorMsg);
            status = STATUS_FAILED;
        }
    }

    // ==================== 通知 ====================

    private Notification buildNotification(String text) {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, GlassApp.CHANNEL_ID)
                .setContentTitle("GlassProtector")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setProgress(0, 0, true)
                .build();
    }

    private void updateNotification(String text) {
        Notification notification = buildNotification(text);
        android.app.NotificationManager manager =
                (android.app.NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification);
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        isRunning = false;
    }
}
