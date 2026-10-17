package com.glass.protector;

import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;

import com.glass.protector.service.ProtectConfig;
import com.glass.protector.service.ProtectService;

import java.io.File;
import java.util.List;

public class ProtectResultActivity extends AppCompatActivity {

    private ImageView resultIcon;
    private TextView resultTitle, resultEngine, resultLevel, resultOutput, resultSize, resultTime, resultLog;
    private Button installBtn, shareBtn, backBtn;

    private ProtectConfig config;
    private String outputApkPath;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Runnable logUpdater;
    private final StringBuilder shownLogs = new StringBuilder();
    private int shownLineCount = 0;
    private boolean finished = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_protect_result);

        config = (ProtectConfig) getIntent().getSerializableExtra(ProtectService.EXTRA_CONFIG);

        initViews();
        setupListeners();
        startLogMonitoring();
    }

    private void initViews() {
        resultIcon = findViewById(R.id.resultIcon);
        resultTitle = findViewById(R.id.resultTitle);
        resultEngine = findViewById(R.id.resultEngine);
        resultLevel = findViewById(R.id.resultLevel);
        resultOutput = findViewById(R.id.resultOutput);
        resultSize = findViewById(R.id.resultSize);
        resultTime = findViewById(R.id.resultTime);
        resultLog = findViewById(R.id.resultLog);
        installBtn = findViewById(R.id.resultInstallBtn);
        shareBtn = findViewById(R.id.resultShareBtn);
        backBtn = findViewById(R.id.resultBackBtn);

        if (config != null) {
            String engineName = "Glass自研加固（DEX加密+混淆）";
            String levelName = config.getLevel() == ProtectConfig.Level.LOW ? "低强度" :
                    config.getLevel() == ProtectConfig.Level.HIGH ? "高强度" : "中强度";
            resultEngine.setText("加固引擎: " + engineName);
            resultLevel.setText("加固强度: " + levelName);
            resultOutput.setText("输出目录: " + config.getOutputDir());
        }

        // 初始显示加固中
        resultIcon.setImageResource(R.drawable.ic_shield);
        resultTitle.setText(R.string.protecting);
        resultLog.setText("[*] 正在加固，等待日志...\n");
    }

    private void setupListeners() {
        installBtn.setOnClickListener(v -> installApk());
        shareBtn.setOnClickListener(v -> shareApk());
        backBtn.setOnClickListener(v -> finish());
    }

    /**
     * 轮询 ProtectService.ProtectState，展示真实日志与真实结果。
     */
    private void startLogMonitoring() {
        logUpdater = new Runnable() {
            @Override
            public void run() {
                if (finished) {
                    return;
                }

                // 追加新增日志
                List<String> logs = ProtectService.ProtectState.snapshotLogs();
                while (shownLineCount < logs.size()) {
                    String line = logs.get(shownLineCount++);
                    shownLogs.append(line).append('\n');
                }
                resultLog.setText(shownLogs.toString());

                int status = ProtectService.ProtectState.status;
                if (status == ProtectService.ProtectState.STATUS_SUCCESS) {
                    onProtectComplete();
                } else if (status == ProtectService.ProtectState.STATUS_FAILED) {
                    onProtectFailed();
                } else {
                    handler.postDelayed(this, 400);
                }
            }
        };
        handler.postDelayed(logUpdater, 300);
    }

    private void onProtectComplete() {
        finished = true;
        resultIcon.setImageResource(R.drawable.ic_success);
        resultTitle.setText(R.string.protect_success);

        outputApkPath = ProtectService.ProtectState.outputPath;
        File outputFile = outputApkPath != null ? new File(outputApkPath) : null;

        if (outputFile != null && outputFile.exists()) {
            resultSize.setText("输出大小: " + formatSize(outputFile.length()));
        } else {
            resultSize.setText("输出大小: 未知（文件不存在）");
        }
        resultTime.setText("加固耗时: " + formatTime(ProtectService.ProtectState.elapsedMs));
        resultOutput.setText("输出文件: " + outputApkPath);
    }

    private void onProtectFailed() {
        finished = true;
        resultIcon.setImageResource(R.drawable.ic_error);
        resultTitle.setText("加固失败");
        resultSize.setText("");
        resultTime.setText("加固耗时: " + formatTime(ProtectService.ProtectState.elapsedMs));
        resultOutput.setText("输出目录: " + (config != null ? config.getOutputDir() : "未知"));
        Toast.makeText(this, "加固失败: " + ProtectService.ProtectState.errorMsg,
                Toast.LENGTH_LONG).show();
    }

    private void installApk() {
        if (outputApkPath == null) {
            Toast.makeText(this, "加固尚未完成", Toast.LENGTH_SHORT).show();
            return;
        }
        File apkFile = new File(outputApkPath);
        if (!apkFile.exists()) {
            Toast.makeText(this, "输出文件不存在", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent intent = new Intent(Intent.ACTION_VIEW);
        Uri uri;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", apkFile);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } else {
            uri = Uri.fromFile(apkFile);
        }
        intent.setDataAndType(uri, "application/vnd.android.package-archive");
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
    }

    private void shareApk() {
        if (outputApkPath == null) {
            Toast.makeText(this, "加固尚未完成", Toast.LENGTH_SHORT).show();
            return;
        }
        File apkFile = new File(outputApkPath);
        if (!apkFile.exists()) {
            Toast.makeText(this, "输出文件不存在", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("application/vnd.android.package-archive");
        Uri uri;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", apkFile);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } else {
            uri = Uri.fromFile(apkFile);
        }
        intent.putExtra(Intent.EXTRA_STREAM, uri);
        startActivity(Intent.createChooser(intent, "分享加固后的APK"));
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.2f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024));
    }

    private String formatTime(long ms) {
        if (ms < 1000) return ms + "ms";
        return String.format("%.1fs", ms / 1000.0);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (logUpdater != null) {
            handler.removeCallbacks(logUpdater);
        }
    }
}
