package com.luoye.dpt.config;

/**
 * 壳配置 - 从dpt-shell移植，修复了配置序列化bug
 */
public class ShellConfig {

    private static ShellConfig instance;

    private String applicationName;
    private String appComponentFactory;
    private boolean debuggable;
    private boolean verifySign;
    private boolean antiDebug;
    private boolean crcDetect;
    private boolean fridaDetect;
    private String signHash;
    private int sdkVersion;

    private ShellConfig() {
        this.debuggable = false;
        this.verifySign = false;
        this.antiDebug = true;
        this.crcDetect = true;
        this.fridaDetect = true;
        this.sdkVersion = 21;
    }

    public static synchronized ShellConfig getInstance() {
        if (instance == null) {
            instance = new ShellConfig();
        }
        return instance;
    }

    public static void reset() {
        instance = null;
    }

    // Getters and Setters
    public String getApplicationName() { return applicationName; }
    public void setApplicationName(String applicationName) { this.applicationName = applicationName; }

    public String getAppComponentFactory() { return appComponentFactory; }
    public void setAppComponentFactory(String appComponentFactory) { this.appComponentFactory = appComponentFactory; }

    public boolean isDebuggable() { return debuggable; }
    public void setDebuggable(boolean debuggable) { this.debuggable = debuggable; }

    public boolean isVerifySign() { return verifySign; }
    public void setVerifySign(boolean verifySign) { this.verifySign = verifySign; }

    public boolean isAntiDebug() { return antiDebug; }
    public void setAntiDebug(boolean antiDebug) { this.antiDebug = antiDebug; }

    public boolean isCrcDetect() { return crcDetect; }
    public void setCrcDetect(boolean crcDetect) { this.crcDetect = crcDetect; }

    public boolean isFridaDetect() { return fridaDetect; }
    public void setFridaDetect(boolean fridaDetect) { this.fridaDetect = fridaDetect; }

    public String getSignHash() { return signHash; }
    public void setSignHash(String signHash) { this.signHash = signHash; }

    public int getSdkVersion() { return sdkVersion; }
    public void setSdkVersion(int sdkVersion) { this.sdkVersion = sdkVersion; }
}
