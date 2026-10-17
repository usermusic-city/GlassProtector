# GlassProtector - 玻璃透明APK加固工具

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-7.0%2B-brightgreen.svg)](https://developer.android)
[![MinSdk](https://img.shields.io/badge/minSdk-24-orange.svg)](https://developer.android)

## 项目简介

GlassProtector 是一款基于 **玻璃拟态（Glassmorphism）UI设计** 的 Android APK 加固工具，内置自研 Glass 加固引擎，支持多强度可选。

### Glass 自研加固引擎

| 引擎 | 类型 | 核心技术 | 来源 |
|------|------|---------|------|
| **Glass自研加固** | DEX加密壳 | AES-128-CBC DEX加密 + 字符串混淆 + 反调试 + 签名校验 + 卢恩字符混淆 | 完全自主研发 |

### 玻璃透明UI特性

- 毛玻璃卡片效果（半透明白 + 边框 + 圆角）
- 深色渐变背景 + 动态光斑
- 玻璃风格按钮、开关、进度条
- 沉浸式状态栏/导航栏

## 功能特性

### Glass自研加固（DEX加密壳）

- ✅ AES-128-CBC DEX加密（运行时内存解密）
- ✅ 字符串常量池加密
- ✅ 反调试检测（ptrace + Frida + 调试端口 + TracerPid）
- ✅ SHA-256签名校验
- ✅ 资源混淆（资源名重命名 + arsc混淆）
- ✅ 垃圾代码注入（控制流平坦化 + 不透明谓词）
- ✅ 卢恩字符混淆（类名/方法名/包名 Elder Futhark 符文映射）
- ✅ 三档强度可选（低/中/高）

## 项目结构

```
GlassProtector/
├── app/                          # 主应用模块
│   ├── src/main/
│   │   ├── java/com/glass/protector/
│   │   │   ├── GlassApp.java              # Application类
│   │   │   ├── MainActivity.java          # 主界面
│   │   │   ├── ProtectResultActivity.java # 加固结果页
│   │   │   ├── ui/
│   │   │   │   ├── HomeFragment.java          # 首页容器
│   │   │   │   └── GlassProtectFragment.java  # Glass加固页面
│   │   │   ├── service/
│   │   │   │   ├── ProtectService.java    # 加固前台服务
│   │   │   │   └── ProtectConfig.java     # 加固配置
│   │   │   └── util/
│   │   │       ├── ApkUtils.java          # APK工具类
│   │   │       ├── GlassProtectorEngine.java # Glass加固引擎
│   │   │       └── RuneObfuscator.java    # 卢恩字符混淆器
│   │   ├── res/
│   │   │   ├── layout/                    # 布局文件
│   │   │   ├── drawable/                  # 玻璃效果drawable
│   │   │   ├── values/                    # 主题/颜色/字符串
│   │   │   └── xml/                       # FileProvider配置
│   │   └── AndroidManifest.xml
│   ├── build.gradle
│   └── proguard-rules.pro
├── shell-runtime/                # 壳运行时模块（编译为shell.dex）
├── build.gradle
├── settings.gradle
├── gradle.properties
└── README.md
```

## 加固强度说明

### 低强度
- 仅开启核心保护（DEX加密）
- 加固速度快，对性能影响最小
- 适合对启动速度要求高的应用

### 中强度（推荐）
- 核心保护 + 字符串加密 + 反调试 + 签名校验
- 安全性与性能的平衡
- 适合大多数应用场景

### 高强度
- 全部保护功能开启
- 包含资源混淆 + 垃圾代码注入 + 卢恩字符混淆 + Dex2C + assets加密
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

# 构建壳运行时 DEX（必须先于 app 构建）
./gradlew :shell-runtime:assembleRelease

# 构建Release版本
./gradlew :app:assembleRelease

# 安装到设备
adb install app/build/outputs/apk/release/app-release.apk
```

## 使用说明

1. 打开 GlassProtector 应用
2. 点击"选择APK文件"，选择需要加固的APK
3. 选择加固强度（低/中/高），或手动配置加固选项
4. 点击"开始加固"
5. 等待加固完成，查看结果页
6. 可直接安装或分享加固后的APK

## 技术原理

### Glass DEX加密壳原理
1. 解析APK，提取所有DEX文件
2. 使用AES-128-CBC加密DEX文件
3. 加密后的DEX存储到assets目录
4. 原DEX替换为最小壳DEX
5. 生成壳DEX（包含ProxyApplication、DexLoader、AntiDebug等）
6. 运行时壳Application启动，解密DEX到内存，通过InMemoryDexClassLoader加载
7. 同时执行反调试检测和签名校验

### 卢恩字符混淆原理
1. 扫描APK内的类名/方法名/包名标识符
2. 将ASCII字符映射为 Elder Futhark 卢恩符文（ᚠᚢᚦᚨᚱᚲ...）
3. 生成双向映射表，混淆后的标识符在虚拟机中仍然合法
4. 映射表写入 assets/rune_obf/ 随加固包分发
5. 加固日志输出混淆统计与前后对照样例

## 注意事项

- 本工具仅供学习和研究使用，请勿用于非法用途
- 加固后的APK需要重新签名才能安装
- 部分使用了加固的应用可能与本工具不兼容
- 建议加固前备份原APK
- 高强度加固可能导致部分应用启动变慢

## 开源许可

本项目基于 MIT License 开源。
