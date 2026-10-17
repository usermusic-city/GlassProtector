package com.glass.protector.util;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * 卢恩字符混淆器（Rune Obfuscator）
 *
 * 原理：
 * 1. 将类名/方法名/包名中的ASCII字符映射为卢恩符文（ᚠᚢᚦᚨᚱᚲ...）
 * 2. 生成双向映射表（原始名 <-> 卢恩名）
 * 3. 在DEX中替换所有类名、方法名、字段名的引用
 * 4. 等价注入解密代码（RuneNameResolver），运行时通过映射表动态恢复
 * 5. 映射表与代码一起加密存储，不影响软件运行
 *
 * 注意：卢恩字符属于Unicode基本多文种平面(BMP)，Java/Android完全支持，
 *       混淆后的类名/方法名在虚拟机中仍然合法可运行。
 */
public class RuneObfuscator {

    // 卢恩符文字母表（24个 Elder Futhark 符文 + 扩展）
    private static final char[] RUNE_ALPHABET = {
            'ᚠ', 'ᚢ', 'ᚦ', 'ᚨ', 'ᚱ', 'ᚲ', 'ᚷ', 'ᚹ', 'ᚺ', 'ᚾ',
            'ᛁ', 'ᛃ', 'ᛇ', 'ᛈ', 'ᛉ', 'ᛊ', 'ᛏ', 'ᛒ', 'ᛖ', 'ᛗ',
            'ᛚ', 'ᛜ', 'ᛞ', 'ᛟ', 'ᛠ', 'ᛢ', 'ᛣ', 'ᛤ', 'ᛥ', 'ᛦ',
            'ᛧ', 'ᛨ', 'ᛩ', 'ᛪ', '᛫', '᛬', '᛭', 'ᛮ', 'ᛯ', 'ᛰ'
    };

    // 字符到卢恩符文的映射
    private final Map<Character, String> charToRuneMap = new HashMap<>();
    // 卢恩符文到字符的映射（用于解密）
    private final Map<String, Character> runeToCharMap = new HashMap<>();
    // 类名/方法名映射表（原始名 -> 混淆名）
    private final Map<String, String> nameMapping = new HashMap<>();
    // 反向映射表（混淆名 -> 原始名），用于注入解密代码
    private final Map<String, String> reverseMapping = new HashMap<>();

    private final Random random;
    private final boolean obfuscateClass;
    private final boolean obfuscateMethod;
    private final boolean obfuscatePackage;

    public RuneObfuscator(boolean obfuscateClass, boolean obfuscateMethod, boolean obfuscatePackage) {
        this.obfuscateClass = obfuscateClass;
        this.obfuscateMethod = obfuscateMethod;
        this.obfuscatePackage = obfuscatePackage;
        this.random = new Random(0x52554E45L); // 固定种子，确保可复现
        initCharMapping();
    }

    /**
     * 初始化字符到卢恩符文的映射
     * 使用多符文组合表示单个ASCII字符，确保唯一性
     */
    private void initCharMapping() {
        // 小写字母 a-z
        for (int i = 0; i < 26; i++) {
            char c = (char) ('a' + i);
            String rune = "" + RUNE_ALPHABET[i % RUNE_ALPHABET.length]
                    + RUNE_ALPHABET[(i / RUNE_ALPHABET.length + 1) % RUNE_ALPHABET.length];
            charToRuneMap.put(c, rune);
            runeToCharMap.put(rune, c);
        }
        // 大写字母 A-Z
        for (int i = 0; i < 26; i++) {
            char c = (char) ('A' + i);
            String rune = "" + RUNE_ALPHABET[(i + 10) % RUNE_ALPHABET.length]
                    + RUNE_ALPHABET[(i + 20) % RUNE_ALPHABET.length];
            charToRuneMap.put(c, rune);
            runeToCharMap.put(rune, c);
        }
        // 数字 0-9
        for (int i = 0; i < 10; i++) {
            char c = (char) ('0' + i);
            String rune = "" + RUNE_ALPHABET[(i + 30) % RUNE_ALPHABET.length];
            charToRuneMap.put(c, rune);
            runeToCharMap.put(rune, c);
        }
        // 下划线
        charToRuneMap.put('_', "" + RUNE_ALPHABET[35]);
        runeToCharMap.put("" + RUNE_ALPHABET[35], '_');
        // 美元符号（内部类使用）
        charToRuneMap.put('$', "" + RUNE_ALPHABET[36]);
        runeToCharMap.put("" + RUNE_ALPHABET[36], '$');
    }

    /**
     * 混淆类名
     */
    public String obfuscateClassName(String originalClassName) {
        if (!obfuscateClass) return originalClassName;
        if (nameMapping.containsKey(originalClassName)) {
            return nameMapping.get(originalClassName);
        }
        // 分离包名和类名
        int lastDot = originalClassName.lastIndexOf('.');
        String packageName = lastDot > 0 ? originalClassName.substring(0, lastDot) : "";
        String simpleClassName = lastDot > 0 ? originalClassName.substring(lastDot + 1) : originalClassName;

        String obfuscatedSimple = obfuscateString(simpleClassName);
        String obfuscatedPackage = obfuscatePackage ? obfuscatePackageName(packageName) : packageName;

        String result = obfuscatedPackage.isEmpty() ? obfuscatedSimple : obfuscatedPackage + "." + obfuscatedSimple;
        nameMapping.put(originalClassName, result);
        reverseMapping.put(result, originalClassName);
        return result;
    }

    /**
     * 混淆方法名
     */
    public String obfuscateMethodName(String originalMethodName) {
        if (!obfuscateMethod) return originalMethodName;
        // 不混淆构造方法和特殊方法
        if (originalMethodName.equals("<init>") || originalMethodName.equals("<clinit>")) {
            return originalMethodName;
        }
        if (nameMapping.containsKey(originalMethodName)) {
            return nameMapping.get(originalMethodName);
        }
        String result = obfuscateString(originalMethodName);
        nameMapping.put(originalMethodName, result);
        reverseMapping.put(result, originalMethodName);
        return result;
    }

    /**
     * 混淆包名
     */
    public String obfuscatePackageName(String originalPackageName) {
        if (!obfuscatePackage || originalPackageName.isEmpty()) return originalPackageName;
        if (nameMapping.containsKey(originalPackageName)) {
            return nameMapping.get(originalPackageName);
        }
        String[] parts = originalPackageName.split("\\.");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) result.append('.');
            result.append(obfuscateString(parts[i]));
        }
        String resultStr = result.toString();
        nameMapping.put(originalPackageName, resultStr);
        reverseMapping.put(resultStr, originalPackageName);
        return resultStr;
    }

    /**
     * 将字符串转换为卢恩符文
     */
    private String obfuscateString(String input) {
        if (input == null || input.isEmpty()) return input;
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            String rune = charToRuneMap.get(c);
            if (rune != null) {
                result.append(rune);
            } else {
                // 未映射的字符保留原样
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * 解密卢恩符文字符串（用于注入的解密代码）
     */
    public String deobfuscateString(String runeString) {
        if (runeString == null || runeString.isEmpty()) return runeString;
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < runeString.length()) {
            // 尝试匹配2个符文的组合
            if (i + 1 < runeString.length()) {
                String twoRunes = "" + runeString.charAt(i) + runeString.charAt(i + 1);
                Character c = runeToCharMap.get(twoRunes);
                if (c != null) {
                    result.append(c);
                    i += 2;
                    continue;
                }
            }
            // 尝试匹配1个符文
            String oneRune = "" + runeString.charAt(i);
            Character c = runeToCharMap.get(oneRune);
            if (c != null) {
                result.append(c);
            } else {
                result.append(runeString.charAt(i));
            }
            i++;
        }
        return result.toString();
    }

    /**
     * 获取完整的映射表（用于序列化到assets，运行时解密使用）
     */
    public Map<String, String> getNameMapping() {
        return new HashMap<>(nameMapping);
    }

    /**
     * 获取反向映射表
     */
    public Map<String, String> getReverseMapping() {
        return new HashMap<>(reverseMapping);
    }

    /**
     * 生成注入用的Java解密代码（RuneNameResolver类）
     * 这段代码会被注入到加固后的APK中，运行时动态恢复类名/方法名
     */
    public String generateResolverCode() {
        StringBuilder sb = new StringBuilder();
        sb.append("package com.glass.protector.runtime;\n\n");
        sb.append("import java.util.HashMap;\n");
        sb.append("import java.util.Map;\n\n");
        sb.append("/**\n");
        sb.append(" * 卢恩字符混淆运行时解析器\n");
        sb.append(" * 由GlassProtector自动注入，用于运行时动态恢复混淆的类名/方法名\n");
        sb.append(" * 映射表与代码一起加密存储，不影响软件正常运行\n");
        sb.append(" */\n");
        sb.append("public class RuneNameResolver {\n\n");
        sb.append("    private static final Map<String, String> NAME_MAP = new HashMap<>();\n");
        sb.append("    private static boolean initialized = false;\n\n");
        sb.append("    static {\n");
        sb.append("        initMapping();\n");
        sb.append("    }\n\n");
        sb.append("    private static native void initMapping();\n\n");
        sb.append("    public static String resolve(String obfuscatedName) {\n");
        sb.append("        if (obfuscatedName == null) return null;\n");
        sb.append("        String original = NAME_MAP.get(obfuscatedName);\n");
        sb.append("        return original != null ? original : obfuscatedName;\n");
        sb.append("    }\n\n");
        sb.append("    public static void putMapping(String obfuscated, String original) {\n");
        sb.append("        NAME_MAP.put(obfuscated, original);\n");
        sb.append("    }\n\n");
        sb.append("    public static boolean isInitialized() {\n");
        sb.append("        return initialized;\n");
        sb.append("    }\n\n");
        sb.append("    public static void setInitialized(boolean value) {\n");
        sb.append("        initialized = value;\n");
        sb.append("    }\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * 生成映射表的JSON表示（用于加密存储到assets）
     */
    public String generateMappingJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"mapping\":{");
        boolean first = true;
        for (Map.Entry<String, String> entry : nameMapping.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":\"")
                    .append(escapeJson(entry.getValue())).append("\"");
            first = false;
        }
        sb.append("}}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * 获取混淆统计信息
     */
    public String getStats() {
        return String.format("卢恩字符混淆统计: 类名=%d, 方法名=%d, 包名=%d, 总映射=%d",
                nameMapping.size(), nameMapping.size(), nameMapping.size(), nameMapping.size());
    }
}
