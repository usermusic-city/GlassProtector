package com.luoye.dpt.config;

/**
 * 常量配置 - 从dpt-shell移植，修复了硬编码路径问题
 */
public class Const {
    public static final String TAG = "dpt";
    public static final String KEY_BUILD_KEY_FILE_NAME = "build-key";
    public static final String SHELL_SO_NAME = "libdpt.so";
    public static final String SHELL_DEX_NAME = "classes.dex";
    public static final String PROTECT_CONFIG_FILE_NAME = "dpt-config.json";
    public static final String CODE_ITEM_FILE_SUFFIX = ".code";
    public static final String MULTI_DEX_CODE_FILE_NAME = "multidexcode.json";
    public static final String APP_NAME_FILE_NAME = "app_name";
    public static final String APP_ACF_FILE_NAME = "app_acf";
    public static final int MIN_SDK_VERSION = 21;
    public static final int DEFAULT_AES_KEY_SIZE = 256;
    public static final int DEFAULT_IV_SIZE = 16;
}
