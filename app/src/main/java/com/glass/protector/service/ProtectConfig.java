package com.glass.protector.service;

import java.io.Serializable;

/**
 * 加固配置 - 支持强度选择和各项开关
 */
public class ProtectConfig implements Serializable {

    public enum Level {
        LOW,    // 低强度
        MEDIUM, // 中强度
        HIGH    // 高强度
    }

    private Level level;
    private String inputApkPath;
    private String outputDir;

    // Glass加固选项
    private boolean dexEncrypt = true;         // DEX加密
    private boolean glassStringEncrypt = true; // 字符串加密
    private boolean glassAntiDebug = true;     // 反调试
    private boolean glassSignVerify = true;    // 签名校验
    private boolean resourceObfuscate = false; // 资源混淆
    private boolean glassJunkCode = false;     // 垃圾代码

    // 高级防护选项
    private boolean dex2cEnabled = false;          // Dex2C（将Java方法转为C native代码）
    private boolean assetsEncryptEnabled = false;  // assets资源加密
    private boolean runeObfuscateEnabled = false;  // 卢恩字符混淆（类名/方法名/包名）
    private boolean runeObfuscateClass = true;     // 混淆类名
    private boolean runeObfuscateMethod = true;    // 混淆方法名
    private boolean runeObfuscatePackage = false;  // 混淆包名

    public ProtectConfig() {
        this.level = Level.MEDIUM;
    }

    // 根据强度自动配置选项
    public void applyLevelPreset() {
        // 高级防护选项
        switch (level) {
            case LOW:
                dex2cEnabled = false;
                assetsEncryptEnabled = false;
                runeObfuscateEnabled = false;
                break;
            case MEDIUM:
                dex2cEnabled = false;
                assetsEncryptEnabled = true;
                runeObfuscateEnabled = false;
                break;
            case HIGH:
                dex2cEnabled = true;
                assetsEncryptEnabled = true;
                runeObfuscateEnabled = true;
                runeObfuscateClass = true;
                runeObfuscateMethod = true;
                runeObfuscatePackage = false;
                break;
        }

        switch (level) {
            case LOW:
                dexEncrypt = true;
                glassStringEncrypt = false;
                glassAntiDebug = false;
                glassSignVerify = false;
                resourceObfuscate = false;
                glassJunkCode = false;
                break;
            case MEDIUM:
                dexEncrypt = true;
                glassStringEncrypt = true;
                glassAntiDebug = true;
                glassSignVerify = true;
                resourceObfuscate = false;
                glassJunkCode = false;
                break;
            case HIGH:
                dexEncrypt = true;
                glassStringEncrypt = true;
                glassAntiDebug = true;
                glassSignVerify = true;
                resourceObfuscate = true;
                glassJunkCode = true;
                break;
        }
    }

    // Getters and Setters
    public Level getLevel() { return level; }
    public void setLevel(Level level) { this.level = level; }

    public String getInputApkPath() { return inputApkPath; }
    public void setInputApkPath(String inputApkPath) { this.inputApkPath = inputApkPath; }

    public String getOutputDir() { return outputDir; }
    public void setOutputDir(String outputDir) { this.outputDir = outputDir; }

    public boolean isDexEncrypt() { return dexEncrypt; }
    public void setDexEncrypt(boolean dexEncrypt) { this.dexEncrypt = dexEncrypt; }

    public boolean isGlassStringEncrypt() { return glassStringEncrypt; }
    public void setGlassStringEncrypt(boolean glassStringEncrypt) { this.glassStringEncrypt = glassStringEncrypt; }

    public boolean isGlassAntiDebug() { return glassAntiDebug; }
    public void setGlassAntiDebug(boolean glassAntiDebug) { this.glassAntiDebug = glassAntiDebug; }

    public boolean isGlassSignVerify() { return glassSignVerify; }
    public void setGlassSignVerify(boolean glassSignVerify) { this.glassSignVerify = glassSignVerify; }

    public boolean isResourceObfuscate() { return resourceObfuscate; }
    public void setResourceObfuscate(boolean resourceObfuscate) { this.resourceObfuscate = resourceObfuscate; }

    public boolean isGlassJunkCode() { return glassJunkCode; }
    public void setGlassJunkCode(boolean glassJunkCode) { this.glassJunkCode = glassJunkCode; }

    // 高级防护选项 getter/setter
    public boolean isDex2cEnabled() { return dex2cEnabled; }
    public void setDex2cEnabled(boolean dex2cEnabled) { this.dex2cEnabled = dex2cEnabled; }

    public boolean isAssetsEncryptEnabled() { return assetsEncryptEnabled; }
    public void setAssetsEncryptEnabled(boolean assetsEncryptEnabled) { this.assetsEncryptEnabled = assetsEncryptEnabled; }

    public boolean isRuneObfuscateEnabled() { return runeObfuscateEnabled; }
    public void setRuneObfuscateEnabled(boolean runeObfuscateEnabled) { this.runeObfuscateEnabled = runeObfuscateEnabled; }

    public boolean isRuneObfuscateClass() { return runeObfuscateClass; }
    public void setRuneObfuscateClass(boolean runeObfuscateClass) { this.runeObfuscateClass = runeObfuscateClass; }

    public boolean isRuneObfuscateMethod() { return runeObfuscateMethod; }
    public void setRuneObfuscateMethod(boolean runeObfuscateMethod) { this.runeObfuscateMethod = runeObfuscateMethod; }

    public boolean isRuneObfuscatePackage() { return runeObfuscatePackage; }
    public void setRuneObfuscatePackage(boolean runeObfuscatePackage) { this.runeObfuscatePackage = runeObfuscatePackage; }
}
