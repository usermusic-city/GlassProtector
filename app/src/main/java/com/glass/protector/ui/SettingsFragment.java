package com.glass.protector.ui;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.glass.protector.R;
import com.glass.protector.util.ApkUtils;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.android.material.textfield.TextInputEditText;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SettingsFragment extends Fragment {

    private static final String PREFS_NAME = "glass_protector_prefs";
    private static final String KEY_KEYSTORE_PATH = "keystore_path";
    private static final String KEY_KEYSTORE_PASS = "keystore_pass";
    private static final String KEY_KEYSTORE_ALIAS = "keystore_alias";
    private static final String KEY_KEYSTORE_ALIAS_PASS = "keystore_alias_pass";
    private static final String KEY_OUTPUT_DIR = "output_dir";
    private static final String KEY_AUTO_SIGN = "auto_sign";
    private static final String KEY_KEEP_ORIGINAL = "keep_original";
    private static final String KEY_SHOW_LOG = "show_log";

    private LinearLayout keystoreInfoLayout;
    private TextView keystoreFileName, keystoreAliasText, outputDirText, cacheSizeText, keystoreVerifyText;
    private TextInputEditText keystorePassEdit, keystoreAliasEdit, keystoreAliasPassEdit;
    private Button importKeystoreBtn, resetOutputDirBtn, chooseOutputDirBtn, cleanCacheBtn, verifyKeystoreBtn;
    private SwitchMaterial autoSignSwitch, keepOriginalSwitch, showLogSwitch;

    private SharedPreferences prefs;
    private String keystorePath;

    private final ActivityResultLauncher<Intent> keystorePicker = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    if (uri != null) {
                        keystorePath = ApkUtils.getPathFromUri(requireContext(), uri);
                        if (keystorePath != null) {
                            prefs.edit().putString(KEY_KEYSTORE_PATH, keystorePath).apply();
                            updateKeystoreInfo();
                            Toast.makeText(requireContext(), "秘钥文件已导入", Toast.LENGTH_SHORT).show();
                        }
                    }
                }
            });

    private final ActivityResultLauncher<Intent> dirPicker = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    if (uri != null) {
                        String dirPath = uri.getPath();
                        if (dirPath != null) {
                            prefs.edit().putString(KEY_OUTPUT_DIR, dirPath).apply();
                            updateOutputDir();
                        }
                    }
                }
            });

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_settings, container, false);
        prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        initViews(view);
        setupListeners();
        loadSettings();
        return view;
    }

    private void initViews(View view) {
        keystoreInfoLayout = view.findViewById(R.id.keystoreInfoLayout);
        keystoreFileName = view.findViewById(R.id.keystoreFileName);
        keystoreAliasText = view.findViewById(R.id.keystoreAlias);
        outputDirText = view.findViewById(R.id.outputDirText);
        keystorePassEdit = view.findViewById(R.id.keystorePassEdit);
        keystoreAliasEdit = view.findViewById(R.id.keystoreAliasEdit);
        keystoreAliasPassEdit = view.findViewById(R.id.keystoreAliasPassEdit);
        keystoreVerifyText = view.findViewById(R.id.keystoreVerifyText);
        verifyKeystoreBtn = view.findViewById(R.id.verifyKeystoreBtn);
        keystoreVerifyText.setVisibility(View.GONE);
        importKeystoreBtn = view.findViewById(R.id.importKeystoreBtn);
        resetOutputDirBtn = view.findViewById(R.id.resetOutputDirBtn);
        chooseOutputDirBtn = view.findViewById(R.id.chooseOutputDirBtn);
        cleanCacheBtn = view.findViewById(R.id.cleanCacheBtn);
        cacheSizeText = view.findViewById(R.id.cacheSizeText);
        autoSignSwitch = view.findViewById(R.id.autoSignSwitch);
        keepOriginalSwitch = view.findViewById(R.id.keepOriginalSwitch);
        showLogSwitch = view.findViewById(R.id.showLogSwitch);
    }

    private void setupListeners() {
        importKeystoreBtn.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            keystorePicker.launch(Intent.createChooser(intent, "选择秘钥文件 (.jks/.bks)"));
        });

        resetOutputDirBtn.setOnClickListener(v -> {
            prefs.edit().remove(KEY_OUTPUT_DIR).apply();
            updateOutputDir();
            Toast.makeText(requireContext(), "已恢复默认导出目录", Toast.LENGTH_SHORT).show();
        });

        chooseOutputDirBtn.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
            dirPicker.launch(intent);
        });

        // 清理缓存：输入 APK 副本 + 加固中间文件 + 历史产物
        cleanCacheBtn.setOnClickListener(v -> confirmCleanCache());

        // 保存密码和别名
        keystorePassEdit.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                String pass = keystorePassEdit.getText().toString();
                prefs.edit().putString(KEY_KEYSTORE_PASS, pass).apply();
            }
        });

        keystoreAliasEdit.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                String alias = keystoreAliasEdit.getText().toString();
                prefs.edit().putString(KEY_KEYSTORE_ALIAS, alias).apply();
                updateKeystoreInfo();
            }
        });

        keystoreAliasPassEdit.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                prefs.edit().putString(KEY_KEYSTORE_ALIAS_PASS,
                        keystoreAliasPassEdit.getText().toString()).apply();
            }
        });

        // 校验秘钥：文件 / 秘钥库密码 / 别名 / 别名密码 四要素逐项验证
        verifyKeystoreBtn.setOnClickListener(v -> verifyKeystore());

        autoSignSwitch.setOnCheckedChangeListener((buttonView, isChecked) ->
                prefs.edit().putBoolean(KEY_AUTO_SIGN, isChecked).apply());
        keepOriginalSwitch.setOnCheckedChangeListener((buttonView, isChecked) ->
                prefs.edit().putBoolean(KEY_KEEP_ORIGINAL, isChecked).apply());
        showLogSwitch.setOnCheckedChangeListener((buttonView, isChecked) ->
                prefs.edit().putBoolean(KEY_SHOW_LOG, isChecked).apply());
    }

    private void loadSettings() {
        keystorePath = prefs.getString(KEY_KEYSTORE_PATH, null);
        String pass = prefs.getString(KEY_KEYSTORE_PASS, "");
        String alias = prefs.getString(KEY_KEYSTORE_ALIAS, "");
        String aliasPass = prefs.getString(KEY_KEYSTORE_ALIAS_PASS, "");
        keystorePassEdit.setText(pass);
        keystoreAliasEdit.setText(alias);
        keystoreAliasPassEdit.setText(aliasPass);
        updateKeystoreInfo();
        updateOutputDir();
        autoSignSwitch.setChecked(prefs.getBoolean(KEY_AUTO_SIGN, true));
        keepOriginalSwitch.setChecked(prefs.getBoolean(KEY_KEEP_ORIGINAL, true));
        showLogSwitch.setChecked(prefs.getBoolean(KEY_SHOW_LOG, false));
        updateCacheInfo();
    }

    // ==================== 秘钥配置与校验 ====================

    /** 供加固流程调用：把用户配置的自定义签名秘钥注入 config（未配置/文件丢失则保持默认内置秘钥） */
    public static void applyKeystoreConfig(Context ctx, com.glass.protector.service.ProtectConfig config) {
        SharedPreferences p = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String path = p.getString(KEY_KEYSTORE_PATH, null);
        if (path == null || path.isEmpty() || !new File(path).exists()) {
            return; // 用引擎内置 glass.p12
        }
        config.setKeystorePath(path);
        config.setKeystorePass(p.getString(KEY_KEYSTORE_PASS, ""));
        config.setKeystoreAlias(p.getString(KEY_KEYSTORE_ALIAS, ""));
        config.setKeystoreAliasPass(p.getString(KEY_KEYSTORE_ALIAS_PASS, ""));
    }

    /** 校验按钮：四要素逐项验证，结果显示在按钮下方 */
    private void verifyKeystore() {
        // 先落盘当前输入框内容
        prefs.edit()
                .putString(KEY_KEYSTORE_PASS, keystorePassEdit.getText().toString())
                .putString(KEY_KEYSTORE_ALIAS, keystoreAliasEdit.getText().toString())
                .putString(KEY_KEYSTORE_ALIAS_PASS, keystoreAliasPassEdit.getText().toString())
                .apply();

        if (keystorePath == null || !new File(keystorePath).exists()) {
            showVerifyResult(false, "未导入秘钥文件");
            return;
        }
        String err;
        try {
            err = com.glass.protector.util.KeyStoreUtils.verifyKeystore(
                    keystorePath,
                    keystorePassEdit.getText().toString(),
                    keystoreAliasEdit.getText().toString(),
                    keystoreAliasPassEdit.getText().toString());
        } catch (Exception e) {
            err = "校验异常: " + e.getMessage();
        }
        if (err == null) {
            String alias = keystoreAliasEdit.getText().toString();
            showVerifyResult(true, "秘钥校验通过，签名将使用别名 " + alias);
        } else {
            showVerifyResult(false, err);
        }
    }

    private void showVerifyResult(boolean ok, String msg) {
        keystoreVerifyText.setVisibility(View.VISIBLE);
        keystoreVerifyText.setText((ok ? "✓ " : "✗ ") + msg);
        keystoreVerifyText.setTextColor(ok ? 0xFF4CAF50 : 0xFFF44336);
    }

    // ==================== 缓存清理 ====================

    /** 刷新可清理缓存统计 */
    private void updateCacheInfo() {
        List<File> targets = new ArrayList<>();
        collectCacheTargets(targets);
        long bytes = 0;
        int files = 0;
        for (File f : targets) {
            bytes += dirSize(f);
            files += countFiles(f);
        }
        cacheSizeText.setText(files == 0
                ? "暂无可清理缓存"
                : "可清理: " + files + " 个文件 / " + fmtSize(bytes));
    }

    /** 收集清理目标：cache 输入副本 + glass_work_* 中间目录 + *_glass_protected.apk 历史产物 */
    private void collectCacheTargets(List<File> targets) {
        Context ctx = requireContext();
        // 1. 本 APP cache 目录（文件选择器复制的输入 APK 副本等）
        File[] cacheFiles = ctx.getCacheDir().listFiles();
        if (cacheFiles != null) {
            for (File f : cacheFiles) targets.add(f);
        }
        // 2. 导出目录：中间目录与历史加固产物
        File out = new File(getOutputDir(ctx));
        File[] outFiles = out.listFiles();
        if (outFiles != null) {
            for (File f : outFiles) {
                if (f.isDirectory() && f.getName().startsWith("glass_work_")) {
                    targets.add(f);
                } else if (f.isFile() && f.getName().endsWith("_glass_protected.apk")) {
                    targets.add(f);
                }
            }
        }
    }

    private void confirmCleanCache() {
        // 用户要求：点击直接清理，不要确认弹窗
        List<File> targets = new ArrayList<>();
        collectCacheTargets(targets);
        if (targets.isEmpty()) {
            Toast.makeText(requireContext(), "没有可清理的缓存", Toast.LENGTH_SHORT).show();
            return;
        }
        doCleanCache(targets);
    }

    private void doCleanCache(List<File> targets) {
        long freed = 0;
        for (File f : targets) {
            freed += dirSize(f);
            deleteRecursively(f);
        }
        updateCacheInfo();
        Toast.makeText(requireContext(), "已清理 " + fmtSize(freed), Toast.LENGTH_SHORT).show();
    }

    private static long dirSize(File f) {
        if (f == null || !f.exists()) return 0;
        if (f.isFile()) return f.length();
        long s = 0;
        File[] list = f.listFiles();
        if (list != null) {
            for (File c : list) s += dirSize(c);
        }
        return s;
    }

    private static int countFiles(File f) {
        if (f == null || !f.exists()) return 0;
        if (f.isFile()) return 1;
        int n = 0;
        File[] list = f.listFiles();
        if (list != null) {
            for (File c : list) n += countFiles(c);
        }
        return n;
    }

    private static void deleteRecursively(File f) {
        if (f == null || !f.exists()) return;
        File[] list = f.listFiles();
        if (list != null) {
            for (File c : list) deleteRecursively(c);
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    private static String fmtSize(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.US, "%.1f KB", b / 1024.0);
        return String.format(Locale.US, "%.1f MB", b / 1024.0 / 1024.0);
    }

    private void updateKeystoreInfo() {
        if (keystorePath != null && new File(keystorePath).exists()) {
            keystoreInfoLayout.setVisibility(View.VISIBLE);
            keystoreFileName.setText(new File(keystorePath).getName());
            String alias = prefs.getString(KEY_KEYSTORE_ALIAS, "");
            keystoreAliasText.setText("别名: " + (alias.isEmpty() ? "未设置" : alias));
        } else {
            keystoreInfoLayout.setVisibility(View.GONE);
        }
    }

    private void updateOutputDir() {
        String dir = prefs.getString(KEY_OUTPUT_DIR, null);
        if (dir == null) {
            // 默认: Android/data/包名/files/
            dir = requireContext().getExternalFilesDir(null) != null ?
                    requireContext().getExternalFilesDir(null).getAbsolutePath() :
                    Environment.getExternalStorageDirectory() + "/Android/data/" +
                            requireContext().getPackageName() + "/files";
        }
        outputDirText.setText(dir);
    }

    /**
     * 获取当前导出目录（供其他类调用）
     */
    public static String getOutputDir(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String dir = prefs.getString(KEY_OUTPUT_DIR, null);
        if (dir == null) {
            dir = context.getExternalFilesDir(null) != null ?
                    context.getExternalFilesDir(null).getAbsolutePath() :
                    Environment.getExternalStorageDirectory() + "/Android/data/" +
                            context.getPackageName() + "/files";
        }
        File file = new File(dir);
        if (!file.exists()) file.mkdirs();
        return dir;
    }
}
