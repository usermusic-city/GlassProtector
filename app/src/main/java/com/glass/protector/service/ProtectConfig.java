package com.glass.protector.service;

import java.io.Serializable;

/**
 * 加固配置 - 支持强度选择和各项开关
 */
public class ProtectConfig implements Serializable {

    public enum Engine {
        DPT,    // DPT魔改加固（函数抽取壳）
        GLASS   // 自研Glass加固（DEX加密+混淆）
    }

    public enum Level {
        LOW,    // 低强度
        MEDIUM, // 中强度
        HIGH    // 高强度
    }

    private Engine engine;
    private Level level;
    private String inputApkPath;
    private String outputDir;

    // DPT加固选项
    private boolean methodExtract = true;      // 方法抽取
    private boolean dptStringEncrypt = true;   // 字符串加密
    private boolean dptAntiDebug = false;      // 反调试
    private boolean dptSignVerify = false;     // 签名校验
    private boolean dptJunkCode = false;       // 垃圾代码

    // Glass加固选项
    private boolean dexEncrypt = true;         // DEX加密
    private boolean glassStringEncrypt = true; // 字符串加密
    private boolean glassAntiDebug = true;     // 反调试
    private boolean glassSignVerify = true;    // 签名校验
    private boolean resourceObfuscate = false; // 资源混淆
    private boolean glassJunkCode = false;     // 垃圾代码

    // 通用高级防护选项（双引擎共用）
    private boolean dex2cEnabled = false;          // Dex2C（将Java方法转为C native代码）
    private boolean assetsEncryptEnabled = false;  // assets资源加密
    private boolean runeObfuscateEnabled = false;  // 卢恩字符混淆（类名/方法名/包名）
    private boolean runeObfuscateClass = true;     // 混淆类名
    private boolean runeObfuscateMethod = true;    // 混淆方法名
    private boolean runeObfuscatePackage = false;  // 混淆包名

    public ProtectConfig() {
        this.engine = Engine.DPT;
        this.level = Level.MEDIUM;
    }

    // 根据强度自动配置选项
    public void applyLevelPreset() {
        // 通用高级防护选项（双引擎共用）
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

        if (engine == Engine.DPT) {
            switch (level) {
                case LOW:
                    methodExtract = true;
                    dptStringEncrypt = false;
                    dptAntiDebug = false;
                    dptSignVerify = false;
                    dptJunkCode = false;
                    break;
                case MEDIUM:
                    methodExtract = true;
                    dptStringEncrypt = true;
                    dptAntiDebug = false;
                    dptSignVerify = false;
                    dptJunkCode = false;
                    break;
                case HIGH:
                    methodExtract = true;
                    dptStringEncrypt = true;
                    dptAntiDebug = true;
                    dptSignVerify = true;
                    dptJunkCode = true;
                    break;
            }
        } else {
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
    }

    // Getters and Setters
    public Engine getEngine() { return engine; }
    public void setEngine(Engine engine) { this.engine = engine; }

    public Level getLevel() { return level; }
    public void setLevel(Level level) { this.level = level; }

    public String getInputApkPath() { return inputApkPath; }
    public void setInputApkPath(String inputApkPath) { this.inputApkPath = inputApkPath; }

    public String getOutputDir() { return outputDir; }
    public void setOutputDir(String outputDir) { this.outputDir = outputDir; }

    public boolean isMethodExtract() { return methodExtract; }
    public void setMethodExtract(boolean methodExtract) { this.methodExtract = methodExtract; }

    public boolean isDptStringEncrypt() { return dptStringEncrypt; }
    public void setDptStringEncrypt(boolean dptStringEncrypt) { this.dptStringEncrypt = dptStringEncrypt; }

    public boolean isDptAntiDebug() { return dptAntiDebug; }
    public void setDptAntiDebug(boolean dptAntiDebug) { this.dptAntiDebug = dptAntiDebug; }

    public boolean isDptSignVerify() { return dptSignVerify; }
    public void setDptSignVerify(boolean dptSignVerify) { this.dptSignVerify = dptSignVerify; }

    public boolean isDptJunkCode() { return dptJunkCode; }
    public void setDptJunkCode(boolean dptJunkCode) { this.dptJunkCode = dptJunkCode; }

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

    // 通用高级防护选项 getter/setter
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
