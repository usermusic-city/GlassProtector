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

    // 自定义签名秘钥（为空时使用内置 glass.p12）
    private String keystorePath;     // 秘钥文件路径 (.jks/.bks/.p12/.pfx/.keystore)
    private String keystorePass;     // 秘钥库密码 (Keystore Password)
    private String keystoreAlias;    // 密钥别名 (Alias)
    private String keystoreAliasPass; // 别名密码 (Key Password，与秘钥库密码相同时可不填)

    // Glass加固选项
    private boolean dexEncrypt = true;         // DEX加密
    private boolean glassStringEncrypt = true; // 资产名随机化
    private boolean glassAntiDebug = true;     // 反调试
    private boolean glassSignVerify = true;    // 签名校验
    private boolean resourceObfuscate = false; // 资源混淆
    private boolean glassJunkCode = false;     // 垃圾代码
    private boolean controlFlowObfuscate = false; // 控制流混淆（dexlib2 指令流改写）

    public ProtectConfig() {
        this.level = Level.MEDIUM;
    }

    // 根据强度自动配置选项
    public void applyLevelPreset() {
        switch (level) {
            case LOW:
                dexEncrypt = true;
                glassStringEncrypt = false;
                glassAntiDebug = false;
                glassSignVerify = false;
                resourceObfuscate = false;
                glassJunkCode = false;
                controlFlowObfuscate = false;
                break;
            case MEDIUM:
                dexEncrypt = true;
                glassStringEncrypt = true;
                glassAntiDebug = true;
                glassSignVerify = true;
                resourceObfuscate = false;
                glassJunkCode = false;
                controlFlowObfuscate = false;
                break;
            case HIGH:
                dexEncrypt = true;
                glassStringEncrypt = true;
                glassAntiDebug = true;
                glassSignVerify = true;
                resourceObfuscate = true;
                glassJunkCode = true;
                controlFlowObfuscate = true;
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

    public String getKeystorePath() { return keystorePath; }
    public void setKeystorePath(String keystorePath) { this.keystorePath = keystorePath; }
    public String getKeystorePass() { return keystorePass; }
    public void setKeystorePass(String keystorePass) { this.keystorePass = keystorePass; }
    public String getKeystoreAlias() { return keystoreAlias; }
    public void setKeystoreAlias(String keystoreAlias) { this.keystoreAlias = keystoreAlias; }
    public String getKeystoreAliasPass() { return keystoreAliasPass; }
    public void setKeystoreAliasPass(String keystoreAliasPass) { this.keystoreAliasPass = keystoreAliasPass; }

    /** 用户是否配置了自定义签名秘钥（路径非空且文件存在） */
    public boolean hasCustomKeystore() {
        return keystorePath != null && !keystorePath.isEmpty() && new java.io.File(keystorePath).exists();
    }

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

    public boolean isControlFlowObfuscate() { return controlFlowObfuscate; }
    public void setControlFlowObfuscate(boolean controlFlowObfuscate) { this.controlFlowObfuscate = controlFlowObfuscate; }
}
