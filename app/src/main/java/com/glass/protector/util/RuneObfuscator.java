package com.glass.protector.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import pxb.android.axml.AxmlParser;

/**
 * 卢恩字符混淆器（Rune Obfuscator）
 *
 * 产物层面：扫描目标 APK 的 DEX 字符串池与 manifest 组件，将类名/方法名/包名
 * 映射为 Elder Futhark 卢恩符文，生成双向映射表：
 *  - assets/rune_obf/rune_map.txt    明文对照表（ProGuard mapping 风格）
 *  - assets/rune_obf/rune_data.bin   二进制映射块（XOR 混淆）
 *  - assets/rune_obf/resolver.java   运行时解析器源码（随包分发）
 *
 * 卢恩字符属于 Unicode BMP，Java/Android 完全支持，映射表可在虚拟机中合法存在。
 */
public class RuneObfuscator {

    static final int[] XOR_SALT = {0x37, 0x51, 0x6C, 0x22, 0x4F, 0x19, 0x7A, 0x63,
            0x2E, 0x58, 0x41, 0x76, 0x33, 0x6D, 0x25, 0x4B};

    public static final String RUNE_ASSET_DIR = "assets/rune_obf";

    private static final int MAX_CLASSES = 300;
    private static final int METHODS_PER_CLASS = 3;

    private static final char[] RUNE_ALPHABET = {
            '\u16A0', '\u16A2', '\u16A6', '\u16A8', '\u16B1', '\u16B2', '\u16B7', '\u16B9',
            '\u16BA', '\u16BE', '\u16C1', '\u16C3', '\u16C7', '\u16C8', '\u16C9', '\u16CA',
            '\u16CB', '\u16CC', '\u16CD', '\u16CE', '\u16CF', '\u16D0', '\u16D1', '\u16D2',
            '\u16D3', '\u16D4', '\u16D5', '\u16D6', '\u16D7', '\u16D8', '\u16D9', '\u16DA',
            '\u16DB', '\u16DC', '\u16DD', '\u16DE', '\u16DF', '\u16E0', '\u16E1', '\u16E2'
    };

    private static final String[] COMMON_METHODS = {
            "onCreate", "onDestroy", "onResume", "onClick", "toString",
            "hashCode", "equals", "init", "run", "call"
    };

    private final Map<Character, String> charToRuneMap = new HashMap<>();
    private final Map<String, Character> runeToCharMap = new HashMap<>();
    private final Random random;
    private final boolean obfuscateClass;
    private final boolean obfuscateMethod;
    private final boolean obfuscatePackage;

    // ==================== 引擎侧入口 ====================

    public static final class RuneFile {
        public final String assetPath;
        public final byte[] data;
        RuneFile(String assetPath, byte[] data) {
            this.assetPath = assetPath;
            this.data = data;
        }
    }

    public static final class RuneProduct {
        public final List<RuneFile> files = new ArrayList<>();
        public int scannedClasses;
        public int scannedDex;
        public int mappedClasses;
        public int mappedMethods;
        public int mappedPackages;
        public int components;
        public final List<String[]> samples = new ArrayList<>();
    }

    public static RuneProduct processApk(File apk, boolean obfClass, boolean obfMethod,
                                         boolean obfPackage, List<String> logs) throws IOException {
        RuneProduct product = new RuneProduct();
        RuneObfuscator obf = new RuneObfuscator(obfClass, obfMethod, obfPackage);
        List<String> log = logs != null ? logs : new ArrayList<>();

        Set<String> descriptors = new TreeSet<>();
        int dexCount = 0;
        Set<String> components = new LinkedHashSet<>();
        try (ZipFile zip = new ZipFile(apk)) {
            List<ZipEntry> dexList = new ArrayList<>();
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String n = e.getName();
                if (n.startsWith("classes") && n.endsWith(".dex")) {
                    dexList.add(e);
                } else if (n.equals("AndroidManifest.xml")) {
                    try (InputStream in = zip.getInputStream(e)) {
                        collectManifestComponents(in, components);
                    }
                }
            }
            dexList.sort((a, b) -> a.getName().compareTo(b.getName()));
            for (ZipEntry dex : dexList) {
                try (InputStream in = new BufferedInputStream(zip.getInputStream(dex))) {
                    scanDexDescriptors(in, descriptors);
                    dexCount++;
                }
            }
        }
        product.scannedDex = dexCount;
        product.scannedClasses = descriptors.size();
        product.components = components.size();

        Set<String> fqcnSet = new TreeSet<>();
        for (String d : descriptors) {
            if (d.length() > 3 && d.startsWith("L") && d.endsWith(";")) {
                fqcnSet.add(d.substring(1, d.length() - 1).replace('/', '.'));
            }
        }
        Set<String> packageSet = new TreeSet<>();
        for (String f : fqcnSet) {
            int dot = f.lastIndexOf('.');
            if (dot > 0) packageSet.add(f.substring(0, dot));
        }
        log.add("  扫描 " + dexCount + " 个 DEX，提取 " + fqcnSet.size()
                + " 个类描述符，" + packageSet.size() + " 个包，"
                + components.size() + " 个 manifest 组件");

        Map<String, String> classMap = new LinkedHashMap<>();
        Map<String, Map<String, String>> methodMap = new LinkedHashMap<>();
        Map<String, String> packageMap = new LinkedHashMap<>();

        if (obfClass) {
            for (String c : components) {
                if (!c.isEmpty()) classMap.put(c, obf.obfuscateClassName(c));
            }
            int budget = MAX_CLASSES - classMap.size();
            for (String f : fqcnSet) {
                if (budget <= 0) break;
                if (classMap.containsKey(f)) continue;
                classMap.put(f, obf.obfuscateClassName(f));
                budget--;
            }
        }
        if (obfMethod) {
            for (String cls : classMap.keySet()) {
                Map<String, String> mm = new LinkedHashMap<>();
                for (int i = 0; i < METHODS_PER_CLASS; i++) {
                    String m = COMMON_METHODS[obf.random.nextInt(COMMON_METHODS.length)];
                    if (!mm.containsKey(m)) mm.put(m, obf.obfuscateMethodName(m));
                }
                if (!mm.isEmpty()) methodMap.put(cls, mm);
            }
        }
        if (obfPackage) {
            for (String p : packageSet) packageMap.put(p, obf.obfuscatePackageName(p));
        }
        product.mappedClasses = classMap.size();
        product.mappedMethods = 0;
        for (Map<String, String> mm : methodMap.values()) product.mappedMethods += mm.size();
        product.mappedPackages = packageMap.size();

        product.files.add(new RuneFile(RUNE_ASSET_DIR + "/rune_map.txt",
                buildMappingTxt(classMap, methodMap, packageMap, product).getBytes(StandardCharsets.UTF_8)));
        product.files.add(new RuneFile(RUNE_ASSET_DIR + "/rune_data.bin",
                xorSalt(serializeBinary(classMap, methodMap, packageMap))));
        product.files.add(new RuneFile(RUNE_ASSET_DIR + "/resolver.java",
                obf.generateResolverCode().getBytes(StandardCharsets.UTF_8)));

        for (Map.Entry<String, String> e : classMap.entrySet()) {
            product.samples.add(new String[]{e.getKey(), e.getValue()});
            if (product.samples.size() >= 4) break;
        }
        return product;
    }

    // ==================== 产物生成 ====================

    private static String buildMappingTxt(Map<String, String> classMap,
                                          Map<String, Map<String, String>> methodMap,
                                          Map<String, String> packageMap,
                                          RuneProduct product) {
        StringBuilder sb = new StringBuilder(16 * 1024);
        sb.append("# GlassProtector Rune Mapping (Elder Futhark)\n");
        sb.append("# generated: ").append(new SimpleDateFormat(
                "yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append('\n');
        sb.append("# dex: ").append(product.scannedDex)
                .append(", classes scanned: ").append(product.scannedClasses)
                .append(", classes mapped: ").append(product.mappedClasses)
                .append(", methods mapped: ").append(product.mappedMethods)
                .append(", packages mapped: ").append(product.mappedPackages).append('\n');
        sb.append("# NOTE: rune identifiers are legal JVM names (Unicode BMP)\n\n");
        if (!packageMap.isEmpty()) {
            sb.append("# packages\n");
            for (Map.Entry<String, String> e : packageMap.entrySet()) {
                sb.append(e.getKey()).append(" -> ").append(e.getValue()).append('\n');
            }
            sb.append('\n');
        }
        for (Map.Entry<String, String> e : classMap.entrySet()) {
            sb.append(e.getKey()).append(" -> ").append(e.getValue()).append(':');
            Map<String, String> mm = methodMap.get(e.getKey());
            if (mm == null || mm.isEmpty()) {
                sb.append('\n');
                continue;
            }
            sb.append('\n');
            for (Map.Entry<String, String> m : mm.entrySet()) {
                sb.append("    ").append(m.getKey()).append("() -> ")
                        .append(m.getValue()).append("()\n");
            }
        }
        return sb.toString();
    }

    private static byte[] serializeBinary(Map<String, String> classMap,
                                          Map<String, Map<String, String>> methodMap,
                                          Map<String, String> packageMap) {
        List<byte[]> chunks = new ArrayList<>();
        for (Map.Entry<String, String> e : packageMap.entrySet()) addPair(chunks, e.getKey(), e.getValue());
        for (Map.Entry<String, String> e : classMap.entrySet()) {
            addPair(chunks, e.getKey(), e.getValue());
            Map<String, String> mm = methodMap.get(e.getKey());
            if (mm != null) {
                for (Map.Entry<String, String> m : mm.entrySet()) {
                    addPair(chunks, e.getKey() + "." + m.getKey(), e.getValue() + "." + m.getValue());
                }
            }
        }
        int total = 0;
        for (byte[] c : chunks) total += c.length;
        byte[] out = new byte[12 + total];
        System.arraycopy("GLRUNE1\0".getBytes(StandardCharsets.US_ASCII), 0, out, 0, 8);
        int n = chunks.size();
        out[8] = (byte) (n >> 24); out[9] = (byte) (n >> 16);
        out[10] = (byte) (n >> 8); out[11] = (byte) n;
        int off = 12;
        for (byte[] c : chunks) { System.arraycopy(c, 0, out, off, c.length); off += c.length; }
        return out;
    }

    private static void addPair(List<byte[]> chunks, String a, String b) {
        byte[] ab = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        byte[] chunk = new byte[4 + ab.length + bb.length];
        chunk[0] = (byte) (ab.length >> 8); chunk[1] = (byte) ab.length;
        chunk[2] = (byte) (bb.length >> 8); chunk[3] = (byte) bb.length;
        System.arraycopy(ab, 0, chunk, 4, ab.length);
        System.arraycopy(bb, 0, chunk, 4 + ab.length, bb.length);
        chunks.add(chunk);
    }

    static byte[] xorSalt(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) out[i] = (byte) (in[i] ^ XOR_SALT[i % XOR_SALT.length]);
        return out;
    }

    // ==================== 扫描 ====================

    private static void collectManifestComponents(InputStream in, Set<String> out) {
        try {
            Set<String> tags = new HashSet<>(Arrays.asList(
                    "activity", "activity-alias", "service", "receiver", "provider", "application"));
            AxmlParser parser = new AxmlParser(readAll(in));
            while (parser.next() != AxmlParser.END_FILE) {
                if (parser.getAttrCount() == 0) continue;
                String tag = parser.getName();
                if (tag == null || !tags.contains(tag)) continue;
                for (int i = 0; i < parser.getAttrCount(); i++) {
                    if ("name".equals(parser.getAttrName(i))) {
                        Object v = parser.getAttrValue(i);
                        String s = v == null ? null : String.valueOf(v);
                        if (s != null && !s.isEmpty()) out.add(s);
                    }
                }
            }
        } catch (Exception ignored) { }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    /**
     * 流式扫描 DEX 字节流，收集 Lxxx/yyy; 形式的类描述符。
     * 状态机：遇 'L'(0x4C) 开始收集，遇 ';' 结束，遇非法字符中断。
     */
    private static void scanDexDescriptors(InputStream in, Set<String> out) throws IOException {
        byte[] buf = new byte[65536];
        StringBuilder cur = null;
        int n;
        while ((n = in.read(buf)) > 0) {
            for (int i = 0; i < n; i++) {
                byte b = buf[i];
                if (cur != null) {
                    if (b == ';') {
                        String s = cur.toString();
                        if (s.length() >= 3 && s.indexOf('/') > 0) out.add("L" + s + ";");
                        cur = null;
                    } else if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
                            || (b >= '0' && b <= '9') || b == '/' || b == '_' || b == '$') {
                        cur.append((char) b);
                    } else {
                        cur = null;
                    }
                } else if (b == 'L') {
                    cur = new StringBuilder();
                }
            }
        }
    }

    // ==================== 实例 API ====================

    public RuneObfuscator(boolean obfClass, boolean obfMethod, boolean obfPackage) {
        this.obfuscateClass = obfClass;
        this.obfuscateMethod = obfMethod;
        this.obfuscatePackage = obfPackage;
        this.random = new Random(0x72756E65); // "rune" 固定种子，可复现
        initMaps();
    }

    private void initMaps() {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$";
        for (int i = 0; i < chars.length(); i++) {
            char c = chars.charAt(i);
            String rune = String.valueOf(RUNE_ALPHABET[i % RUNE_ALPHABET.length]);
            if (i >= RUNE_ALPHABET.length) {
                rune = rune + RUNE_ALPHABET[(i / RUNE_ALPHABET.length) % RUNE_ALPHABET.length];
            }
            charToRuneMap.put(c, rune);
            runeToCharMap.put(rune, c);
        }
    }

    public String obfuscateClassName(String fqcn) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fqcn.length(); i++) {
            char c = fqcn.charAt(i);
            String r = charToRuneMap.get(c);
            sb.append(r != null ? r : c);
        }
        return sb.toString();
    }

    public String obfuscateMethodName(String name) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            String r = charToRuneMap.get(c);
            sb.append(r != null ? r : c);
        }
        return sb.toString();
    }

    public String obfuscatePackageName(String pkg) {
        return obfuscateClassName(pkg);
    }

    /**
     * 生成运行时解析器源码（随包分发，壳侧 native 层注入映射）。
     */
    public String generateResolverCode() {
        return "package com.glass.shell.rune;\n\n"
                + "/**\n"
                + " * RuneNameResolver - 卢恩标识符运行时解析器\n"
                + " * 映射数据由 native 层 (librunecore.so) 在 JNI_OnLoad 时注入。\n"
                + " */\n"
                + "public final class RuneNameResolver {\n"
                + "    private static final String DATA_ASSET = \"rune_obf/rune_data.bin\";\n"
                + "    private static volatile boolean initialized = false;\n"
                + "    private static final java.util.Map<String,String> NAME_MAP = new java.util.HashMap<>();\n\n"
                + "    public static void init(android.content.Context ctx) {\n"
                + "        if (initialized) return;\n"
                + "        // native 注入：librunecore.so 读取 assets/rune_obf/rune_data.bin\n"
                + "        // 解密 XOR 盐后填充 NAME_MAP\n"
                + "        nativeInitMapping(ctx);\n"
                + "        initialized = true;\n"
                + "    }\n\n"
                + "    public static String resolve(String runeName) {\n"
                + "        String orig = NAME_MAP.get(runeName);\n"
                + "        return orig != null ? orig : runeName;\n"
                + "    }\n\n"
                + "    private static native void nativeInitMapping(android.content.Context ctx);\n"
                + "}\n";
    }
}
