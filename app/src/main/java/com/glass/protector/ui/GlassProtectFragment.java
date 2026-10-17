package com.glass.protector.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.glass.protector.ProtectResultActivity;
import com.glass.protector.R;
import com.glass.protector.service.ProtectConfig;
import com.glass.protector.service.ProtectService;
import com.glass.protector.util.ApkUtils;
import com.google.android.material.switchmaterial.SwitchMaterial;

import java.io.File;

public class GlassProtectFragment extends Fragment {

    private LinearLayout apkInfoLayout;
    private TextView apkNameText, apkSizeText;
    private Button selectApkBtn, startProtectBtn;
    private RadioGroup levelGroup;
    private SwitchMaterial optDexEncrypt, optStringEncrypt, optAntiDebug, optSignVerify,
            optResourceObfuscate, optJunkCode;
    private SwitchMaterial optDex2c, optAssetsEncrypt, optRuneObfuscate;

    private String selectedApkPath;

    private final ActivityResultLauncher<Intent> filePickerLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    if (uri != null) {
                        selectedApkPath = ApkUtils.getPathFromUri(requireContext(), uri);
                        updateApkInfo();
                    }
                }
            });

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_glass_protect, container, false);
        initViews(view);
        setupListeners();
        return view;
    }

    private void initViews(View view) {
        apkInfoLayout = view.findViewById(R.id.glass_apkInfoLayout);
        apkNameText = view.findViewById(R.id.glass_apkName);
        apkSizeText = view.findViewById(R.id.glass_apkSize);
        selectApkBtn = view.findViewById(R.id.glass_selectApkBtn);
        startProtectBtn = view.findViewById(R.id.glass_startProtectBtn);
        levelGroup = view.findViewById(R.id.glass_levelGroup);
        optDexEncrypt = view.findViewById(R.id.glass_optDexEncrypt);
        optStringEncrypt = view.findViewById(R.id.glass_optStringEncrypt);
        optAntiDebug = view.findViewById(R.id.glass_optAntiDebug);
        optSignVerify = view.findViewById(R.id.glass_optSignVerify);
        optResourceObfuscate = view.findViewById(R.id.glass_optResourceObfuscate);
        optJunkCode = view.findViewById(R.id.glass_optJunkCode);
        optDex2c = view.findViewById(R.id.glass_optDex2c);
        optAssetsEncrypt = view.findViewById(R.id.glass_optAssetsEncrypt);
        optRuneObfuscate = view.findViewById(R.id.glass_optRuneObfuscate);
    }

    private void setupListeners() {
        selectApkBtn.setOnClickListener(v -> openFilePicker());

        levelGroup.setOnCheckedChangeListener((group, checkedId) -> {
            ProtectConfig config = new ProtectConfig();
            if (checkedId == R.id.glass_levelLow) {
                config.setLevel(ProtectConfig.Level.LOW);
            } else if (checkedId == R.id.glass_levelHigh) {
                config.setLevel(ProtectConfig.Level.HIGH);
            } else {
                config.setLevel(ProtectConfig.Level.MEDIUM);
            }
            config.applyLevelPreset();
            optDexEncrypt.setChecked(config.isDexEncrypt());
            optStringEncrypt.setChecked(config.isGlassStringEncrypt());
            optAntiDebug.setChecked(config.isGlassAntiDebug());
            optSignVerify.setChecked(config.isGlassSignVerify());
            optResourceObfuscate.setChecked(config.isResourceObfuscate());
            optJunkCode.setChecked(config.isGlassJunkCode());
            optDex2c.setChecked(config.isDex2cEnabled());
            optAssetsEncrypt.setChecked(config.isAssetsEncryptEnabled());
            optRuneObfuscate.setChecked(config.isRuneObfuscateEnabled());
        });

        startProtectBtn.setOnClickListener(v -> startProtect());
    }

    private void openFilePicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/vnd.android.package-archive");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        filePickerLauncher.launch(Intent.createChooser(intent, "选择APK文件"));
    }

    private void updateApkInfo() {
        if (selectedApkPath != null && new File(selectedApkPath).exists()) {
            File apkFile = new File(selectedApkPath);
            apkInfoLayout.setVisibility(View.VISIBLE);
            apkNameText.setText(apkFile.getName());
            apkSizeText.setText(ApkUtils.formatFileSize(apkFile.length()));
        }
    }

    private void startProtect() {
        if (selectedApkPath == null || !new File(selectedApkPath).exists()) {
            Toast.makeText(requireContext(), "请先选择APK文件", Toast.LENGTH_SHORT).show();
            return;
        }

        ProtectConfig config = new ProtectConfig();
        config.setInputApkPath(selectedApkPath);
        config.setOutputDir(Environment.getExternalStorageDirectory() + "/GlassProtector/output");

        int checkedId = levelGroup.getCheckedRadioButtonId();
        if (checkedId == R.id.glass_levelLow) {
            config.setLevel(ProtectConfig.Level.LOW);
        } else if (checkedId == R.id.glass_levelHigh) {
            config.setLevel(ProtectConfig.Level.HIGH);
        } else {
            config.setLevel(ProtectConfig.Level.MEDIUM);
        }

        config.setDexEncrypt(optDexEncrypt.isChecked());
        config.setGlassStringEncrypt(optStringEncrypt.isChecked());
        config.setGlassAntiDebug(optAntiDebug.isChecked());
        config.setGlassSignVerify(optSignVerify.isChecked());
        config.setResourceObfuscate(optResourceObfuscate.isChecked());
        config.setGlassJunkCode(optJunkCode.isChecked());
        config.setDex2cEnabled(optDex2c.isChecked());
        config.setAssetsEncryptEnabled(optAssetsEncrypt.isChecked());
        config.setRuneObfuscateEnabled(optRuneObfuscate.isChecked());

        // 使用设置中配置的导出目录
        config.setOutputDir(SettingsFragment.getOutputDir(requireContext()));

        Intent serviceIntent = new Intent(requireContext(), ProtectService.class);
        serviceIntent.putExtra(ProtectService.EXTRA_CONFIG, config);
        androidx.core.content.ContextCompat.startForegroundService(requireContext(), serviceIntent);

        Intent resultIntent = new Intent(requireContext(), ProtectResultActivity.class);
        resultIntent.putExtra(ProtectService.EXTRA_CONFIG, config);
        startActivity(resultIntent);
    }
}
