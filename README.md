# GlassProtector - 玻璃透明APK加固工具

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-7.0%2B-brightgreen.svg)](https://developer.android.com)
[![MinSdk](https://img.shields.io/badge/minSdk-24-orange.svg)](https://developer.android.com)

## 项目简介

GlassProtector 是一款基于 **玻璃拟态（Glassmorphism）UI设计** 的 Android APK 加固工具，集成了两套独立的加固引擎，支持多强度可选。

### 双加固引擎

| 引擎 | 类型 | 核心技术 | 来源 |
|------|------|---------|------|
| **DPT魔改加固** | 函数抽取壳 | 掏空方法体 + 运行时恢复 + 字符串加密 | 基于 [dpt-shell](https://github.com/luoyesiqiu/dpt-shell) 魔改 |
| **Glass自研加固** | DEX加密壳 | AES-256 DEX加密 + 字符串混淆 + 反调试 + 签名校验 | 完全自主研发 |

### 玻璃透明UI特性

- 毛玻璃卡片效果（半透明白 + 边框 + 圆角）
- 深色渐变背景 + 动态光斑
- 双Tab切换界面
- 玻璃风格按钮、开关、进度条
- 沉浸式状态栏/导航栏

## 功能特性

### DPT魔改加固（函数抽取壳）

- ✅ 方法体抽取（掏空方法实现，运行时动态恢复）
- ✅ 字符串常量加密（XOR + Base64）
- ✅ 反调试检测（可选）
- ✅ 签名校验（可选）
- ✅ 垃圾代码注入（可选）
- ✅ 多DEX支持
- ✅ 三档强度可选（低/中/高）

### Glass自研加固（DEX加密壳）

- ✅ AES-256 DEX加密（CBC模式，运行时内存解密）
- ✅ 字符串常量池加密
- ✅ 反调试检测（ptrace + Frida + 调试端口 + TracerPid）
- ✅ SHA-256签名校验
- ✅ 资源混淆（资源名重命名 + arsc混淆）
- ✅ 垃圾代码注入（控制流平坦化 + 不透明谓词）
- ✅ 三档强度可选（低/中/高）

## 修复的Bug（基于dpt-shell原版）

1. **Android 14+ ClassLoader hook崩溃** - 改用 InMemoryDexClassLoader 替代 hook ClassLoader
2. **多DEX方法抽取索引越界** - 修复了多DEX情况下方法索引计算错误
3. **字符串加密中文乱码** - 统一使用 UTF-8 编码，修复默认编码问题
4. **加固后启动黑屏** - 修复了 ProxyApplication 初始化时序问题
5. **ZIP路径遍历漏洞** - 添加了路径遍历攻击防护
6. **大文件压缩OOM** - 优化了ZIP压缩缓冲区管理
7. **AES密钥长度校验缺失** - 添加了密钥长度合法性校验

## 项目结构

```
GlassProtector/
├── app/                          # 主应用模块
│   ├── src/main/
│   │   ├── java/com/glass/protector/
│   │   │   ├── GlassApp.java              # Application类
│   │   │   ├── MainActivity.java          # 主界面（双Tab）
│   │   │   ├── ProtectResultActivity.java # 加固结果页
│   │   │   ├── ui/
│   │   │   │   ├── DptProtectFragment.java    # DPT加固页面
│   │   │   │   └── GlassProtectFragment.java  # Glass加固页面
│   │   │   ├── service/
│   │   │   │   ├── ProtectService.java    # 加固前台服务
│   │   │   │   └── ProtectConfig.java     # 加固配置
│   │   │   └── util/
│   │   │       ├── ApkUtils.java          # APK工具类
│   │   │       ├── DptProtector.java      # DPT加固引擎
│   │   │       └── GlassProtectorEngine.java # Glass加固引擎
│   │   ├── res/
│   │   │   ├── layout/                    # 布局文件
│   │   │   ├── drawable/                  # 玻璃效果drawable
│   │   │   ├── values/                    # 主题/颜色/字符串
│   │   │   └── xml/                       # FileProvider配置
│   │   └── AndroidManifest.xml
│   ├── build.gradle
│   └── proguard-rules.pro
├── dpt-core/                     # DPT核心库（从dpt-shell移植并修复）
│   ├── src/main/java/com/luoye/dpt/
│   │   ├── config/
│   │   │   ├── Const.java
│   │   │   └── ShellConfig.java
│   │   └── util/
│   │       ├── CryptoUtils.java        # 加密工具（AES/RC4/XOR）
│   │       ├── FileUtils.java
│   │       ├── HexUtils.java
│   │       ├── IoUtils.java
│   │       ├── LogUtils.java
│   │       ├── MessageDigestUtils.java
│   │       ├── StringUtils.java
│   │       └── ZipUtils.java
│   ├── build.gradle
│   └── consumer-rules.pro
├── build.gradle
├── settings.gradle
├── gradle.properties
└── README.md
```

## 加固强度说明

### 低强度
- 仅开启核心保护（方法抽取/DEX加密）
- 加固速度快，对性能影响最小
- 适合对启动速度要求高的应用

### 中强度（推荐）
- 核心保护 + 字符串加密 + 反调试 + 签名校验
- 安全性与性能的平衡
- 适合大多数应用场景

### 高强度
- 全部保护功能开启
- 包含资源混淆 + 垃圾代码注入
- 安全性最高，但加固时间较长，对性能有一定影响

## 构建说明

### 环境要求
- Android Studio Hedgehog (2023.1.1) 或更高
- JDK 17
- Android SDK 34
- Gradle 8.2+

### 构建步骤
```bash
# 克隆项目
git clone <repository-url>
cd GlassProtector

# 构建Debug版本
./gradlew assembleDebug

# 构建Release版本
./gradlew assembleRelease

# 安装到设备
adb install app/build/outputs/apk/debug/app-debug.apk
```

## 使用说明

1. 打开 GlassProtector 应用
2. 选择加固引擎（DPT魔改加固 / Glass自研加固）
3. 点击"选择APK文件"，选择需要加固的APK
4. 选择加固强度（低/中/高），或手动配置加固选项
5. 点击"开始加固"
6. 等待加固完成，查看结果页
7. 可直接安装或分享加固后的APK

## 技术原理

### DPT函数抽取壳原理
1. 解析APK中的DEX文件
2. 遍历所有方法，将方法体（code_item）抽取出来
3. 将抽取的code_item加密后存储到assets目录
4. 原方法体替换为nop指令
5. 注入壳代码（ProxyApplication + Native库）
6. 运行时壳代码解密并恢复方法体，通过hook ClassLoader实现动态加载

### Glass DEX加密壳原理
1. 解析APK，提取所有DEX文件
2. 使用AES-256-CBC加密DEX文件
3. 加密后的DEX存储到assets目录
4. 原DEX替换为最小壳DEX
5. 生成壳DEX（包含ProxyApplication、DexLoader、AntiDebug等）
6. 运行时壳Application启动，解密DEX到内存，通过InMemoryDexClassLoader加载
7. 同时执行反调试检测和签名校验

## 注意事项

- 本工具仅供学习和研究使用，请勿用于非法用途
- 加固后的APK需要重新签名才能安装
- 部分使用了加固的应用可能与本工具不兼容
- 建议加固前备份原APK
- 高强度加固可能导致部分应用启动变慢

## 开源许可

本项目基于 MIT License 开源，其中 dpt-core 模块基于 dpt-shell (MIT License) 修改。

## 致谢

- [dpt-shell](https://github.com/luoyesiqiu/dpt-shell) - 函数抽取壳原理参考
- [Dobby](https://github.com/jmpews/Dobby) - Hook框架参考
