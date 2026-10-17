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

public class SettingsFragment extends Fragment {

    private static final String PREFS_NAME = "glass_protector_prefs";
    private static final String KEY_KEYSTORE_PATH = "keystore_path";
    private static final String KEY_KEYSTORE_PASS = "keystore_pass";
    private static final String KEY_KEYSTORE_ALIAS = "keystore_alias";
    private static final String KEY_OUTPUT_DIR = "output_dir";
    private static final String KEY_AUTO_SIGN = "auto_sign";
    private static final String KEY_KEEP_ORIGINAL = "keep_original";
    private static final String KEY_SHOW_LOG = "show_log";

    private LinearLayout keystoreInfoLayout;
    private TextView keystoreFileName, keystoreAliasText, outputDirText;
    private TextInputEditText keystorePassEdit, keystoreAliasEdit;
    private Button importKeystoreBtn, resetOutputDirBtn, chooseOutputDirBtn;
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
        importKeystoreBtn = view.findViewById(R.id.importKeystoreBtn);
        resetOutputDirBtn = view.findViewById(R.id.resetOutputDirBtn);
        chooseOutputDirBtn = view.findViewById(R.id.chooseOutputDirBtn);
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
        keystorePassEdit.setText(pass);
        keystoreAliasEdit.setText(alias);
        updateKeystoreInfo();
        updateOutputDir();
        autoSignSwitch.setChecked(prefs.getBoolean(KEY_AUTO_SIGN, true));
        keepOriginalSwitch.setChecked(prefs.getBoolean(KEY_KEEP_ORIGINAL, true));
        showLogSwitch.setChecked(prefs.getBoolean(KEY_SHOW_LOG, false));
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
