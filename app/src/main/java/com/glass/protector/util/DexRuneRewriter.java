package com.glass.protector.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.zip.Adler32;

/**
 * DEX 卢恩真改名器（DexRuneRewriter）
 *
 * 与 RuneObfuscator（产物层映射表）不同，本类对 DEX 字符串池做【等长原地替换】，
 * 类名/描述符真实变更为 Elder Futhark 卢恩标识符，运行时加载的就是改名后的类：
 *
 *  原理（等长数学，结构零破坏）：
 *  - DEX string_data_item = uleb128(utf16_size) + MUTF-8 data + 0x00
 *  - ASCII 字符占 1 字节；卢恩 U+16A0..U+16E2 在 MUTF-8 占 3 字节
 *  - 描述符按 L / $ 段化，段内 3 个 ASCII → 1 个卢恩，尾数 b%3 用随机小写字母补齐
 *  - data 字节数不变 → string_ids 偏移不变 → 全部结构偏移不变
 *  - utf16_size 变小但仍 ≤127 → ULEB128 长度不变（>63 的字符串直接跳过）
 *  - 改写完成后仅重算 header SHA-1 signature 与 adler32 checksum
 *
 *  引用同步（自动生效）：
 *  - type_ids/method_ids/field_ids 经 idx 间接引用 string_ids → 改条目即全局同步
 *  - 同名段全局共享映射（com.a.Foo 与 com.b.Foo 的 "Foo" 段一致）
 *  - 普通字符串精确匹配类全名（com.example.Foo 点分形式）也同步替换 → Class.forName 存活
 *
 *  keep 规则（不改名，防止运行时破坏）：
 *  - manifest 组件类（activity/service/receiver/provider/application/factory）
 *  - 含 native 方法的类（JNI 静态绑定 Java_类名_方法名 / 动态注册 FindClass）
 *  - 非 class_defs 定义的类（android./java./kotlin. 等系统引用）
 *  - 方法名混淆仅限：全 DEX 所有使用处均为 private、长度≥5、非常见回调名
 */
public final class DexRuneRewriter {

    private DexRuneRewriter() {
    }

    /** Elder Futhark 40 字符（MUTF-8 3 字节，Unicode BMP 合法 JVM 标识符） */
    private static final char[] RUNES = {
            '\u16A0', '\u16A2', '\u16A6', '\u16A8', '\u16B1', '\u16B2', '\u16B7', '\u16B9',
            '\u16BA', '\u16BE', '\u16C1', '\u16C3', '\u16C7', '\u16C8', '\u16C9', '\u16CA',
            '\u16CB', '\u16CC', '\u16CD', '\u16CE', '\u16CF', '\u16D0', '\u16D1', '\u16D2',
            '\u16D3', '\u16D4', '\u16D5', '\u16D6', '\u16D7', '\u16D8', '\u16D9', '\u16DA',
            '\u16DB', '\u16DC', '\u16DD', '\u16DE', '\u16DF', '\u16E0', '\u16E1', '\u16E2'
    };

    /** 跳过：utf16_size > 63 的字符串（ULEB128 仍 1 字节的上界，保证等长成立） */
    private static final int MAX_STR_CHARS = 63;

    /** 方法名混淆排除：常见回调/反射目标词（误伤普通字符串风险高） */
    private static final Set<String> METHOD_NAME_BLACKLIST = new HashSet<>(Arrays.asList(
            "toString", "valueOf", "getName", "getSimpleName", "run", "call", "init",
            "main", "close", "clone", "equals", "hashCode", "compareTo", "length"));

    /** 方法名最小长度（短名撞普通字符串概率高） */
    private static final int MIN_METHOD_NAME_LEN = 5;

    /** 可复现随机（固定种子，同 APK 多次加固结果一致） */
    private static final long SEED = 0x72756E65L; // "rune"

    // ==================== 结果 ====================

    public static final class Result {
        /** 原描述符 Lcom/a/Foo; → 卢恩描述符（真改名映射，rune_map.txt 内容） */
        public final Map<String, String> classMap = new LinkedHashMap<>();
        /** 原方法名 → 卢恩方法名（仅 private） */
        public final Map<String, String> methodMap = new LinkedHashMap<>();
        /** 段级共享映射（包结构保留，同名段同步） */
        public final Map<String, String> segmentMap = new LinkedHashMap<>();
        public int dexCount;
        public int definedClasses;
        public int keptClasses;
        public int renamedClasses;
        public int renamedMethods;
        public int renamedStrings;
        public int skippedLong;
        public final List<String[]> samples = new ArrayList<>();

        public String mapTxt() {
            StringBuilder sb = new StringBuilder(32 * 1024);
            sb.append("# GlassProtector Rune DEX Mapping (real rename)\n");
            sb.append("# dex=").append(dexCount)
                    .append(" defined=").append(definedClasses)
                    .append(" kept=").append(keptClasses)
                    .append(" renamed=").append(renamedClasses)
                    .append(" methods=").append(renamedMethods)
                    .append(" strings=").append(renamedStrings)
                    .append(" skippedLong=").append(skippedLong).append('\n');
            sb.append("# keep: manifest components + native classes; methods: private only\n\n");
            for (Map.Entry<String, String> e : classMap.entrySet()) {
                sb.append(e.getKey()).append(" -> ").append(e.getValue()).append('\n');
            }
            if (!methodMap.isEmpty()) {
                sb.append("\n# methods (private)\n");
                for (Map.Entry<String, String> e : methodMap.entrySet()) {
                    sb.append(e.getKey()).append(" -> ").append(e.getValue()).append('\n');
                }
            }
            return sb.toString();
        }
    }

    // ==================== 入口 ====================

    /**
     * 全量改写。dexes 的 value 数组将被【原地改写】（等长替换零拷贝），
     * 返回真映射结果。keepClasses：manifest 组件类（点分全名）。
     */
    public static Result rewriteAll(LinkedHashMap<String, byte[]> dexes,
                                    Set<String> keepClasses, boolean obfMethod,
                                    List<String> logs) throws Exception {
        List<String> log = logs != null ? logs : new ArrayList<>();
        Random rand = new Random(SEED);
        Result r = new Result();
        r.dexCount = dexes.size();

        // ---- pass 1：收集所有 DEX 定义的类 + native 类 + 方法名 flags 统计 ----
        Set<String> defined = new LinkedHashSet<>();
        Set<String> nativeClasses = new HashSet<>();
        // 方法名 → 是否存在非 private 使用（true=不安全）
        Map<String, Boolean> methodUnsafe = new LinkedHashMap<>();
        for (byte[] dex : dexes.values()) {
            scanClassDefs(dex, defined, nativeClasses, methodUnsafe);
        }
        r.definedClasses = defined.size();

        // keep 集：manifest 组件（点分→描述符） + native 类
        Set<String> keepDesc = new HashSet<>();
        for (String k : keepClasses) {
            if (k == null || k.isEmpty()) continue;
            String d = k.startsWith("L") ? k : "L" + k.replace('.', '/') + ";";
            if (defined.contains(d)) keepDesc.add(d);
        }
        keepDesc.addAll(nativeClasses);
        keepDesc.retainAll(defined);
        r.keptClasses = keepDesc.size();

        // ---- 生成类名映射（描述符级） ----
        for (String desc : defined) {
            if (keepDesc.contains(desc)) continue;
            if (isFrameworkClass(desc)) continue; // 系统/框架类不改名（防运行时崩溃）
            String newDesc = mapDescriptor(desc, rand, r.segmentMap);
            if (newDesc != null) {
                r.classMap.put(desc, newDesc);
            }
        }
        r.renamedClasses = r.classMap.size();

        // ---- 生成方法名映射（仅全 private 使用、非黑名单） ----
        if (obfMethod) {
            for (Map.Entry<String, Boolean> e : methodUnsafe.entrySet()) {
                String name = e.getKey();
                if (Boolean.TRUE.equals(e.getValue())) continue;
                if (name.length() < MIN_METHOD_NAME_LEN) continue;
                if (METHOD_NAME_BLACKLIST.contains(name)) continue;
                if (!isAsciiIdent(name)) continue;
                r.methodMap.put(name, mapPlainName(name, rand, r.segmentMap));
            }
            r.renamedMethods = r.methodMap.size();
        }

        log.add("  [rune-dex] 定义类 " + defined.size() + "，keep " + keepDesc.size()
                + "（组件+native），改名 " + r.classMap.size()
                + (obfMethod ? "，private 方法名 " + r.methodMap.size() : ""));

        // ---- pass 2：逐 DEX 应用映射（原地等长改写 + checksum 重算） ----
        int entryIdx = 0;
        for (Map.Entry<String, byte[]> e : dexes.entrySet()) {
            int[] stat = applyToDex(e.getValue(), r);
            r.renamedStrings += stat[0];
            r.skippedLong += stat[1];
            log.add("  [rune-dex] " + e.getKey() + ": " + stat[0] + " 条字符串已卢恩化"
                    + (stat[1] > 0 ? "，" + stat[1] + " 条超长跳过" : ""));
            entryIdx++;
        }

        for (Map.Entry<String, String> e : r.classMap.entrySet()) {
            r.samples.add(new String[]{e.getKey(), e.getValue()});
            if (r.samples.size() >= 5) break;
        }
        return r;
    }

    // ==================== 映射生成 ====================

    /**
     * 系统/框架类判定（描述符形式 Lcom/...;）。
     * 这些类被框架/运行时反射按全名加载，改名会导致 ClassNotFoundException，
     * 故一律 keep。覆盖 Android SDK、androidx、support、JVM 标准库、Kotlin、
     * 常见第三方基础库前缀。
     */
    private static boolean isFrameworkClass(String desc) {
        if (!desc.startsWith("L") || !desc.endsWith(";")) return false;
        String body = desc.substring(1, desc.length() - 1);
        if (body.startsWith("android/")) return true;   // android.*（含 android/support/）
        if (body.startsWith("androidx/")) return true;  // androidx.*
        if (body.startsWith("java/")) return true;      // java.*
        if (body.startsWith("javax/")) return true;     // javax.*
        if (body.startsWith("kotlin/")) return true;    // kotlin.*
        if (body.startsWith("kotlinx/")) return true;   // kotlinx.*
        if (body.startsWith("dalvik/")) return true;    // dalvik.*
        if (body.startsWith("junit/")) return true;     // junit.*
        if (body.startsWith("org/apache/")) return true;
        if (body.startsWith("org/json/")) return true;
        if (body.startsWith("org/xml/")) return true;
        if (body.startsWith("org/w3c/")) return true;
        if (body.startsWith("org/junit/")) return true;
        if (body.startsWith("org/xmlpull/")) return true;
        if (body.startsWith("com/google/")) return true; // Gson/Guava/Protobuf 等
        return false;
    }

    /**
     * 描述符映射：Lcom/example/Foo$Bar; → 卢恩描述符。
     * 段按 '/' '$' 划分，段级共享缓存保证同名段全局一致（点分名同步的前提）。
     * 返回 null 表示无法等长替换（跳过）。
     */
    private static String mapDescriptor(String desc, Random rand, Map<String, String> segMap) {
        if (!desc.startsWith("L") || !desc.endsWith(";")) return null;
        if (desc.length() > MAX_STR_CHARS) return null;
        String body = desc.substring(1, desc.length() - 1);
        if (body.isEmpty()) return null;

        StringBuilder out = new StringBuilder(desc.length() + 16);
        out.append('L');
        StringBuilder seg = new StringBuilder();
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '/' || c == '$') {
                if (seg.length() == 0) return null; // 异常描述符
                String mapped = mapSegment(seg.toString(), rand, segMap);
                if (mapped == null) return null;
                out.append(mapped).append(c);
                seg.setLength(0);
            } else {
                seg.append(c);
            }
        }
        if (seg.length() == 0) return null;
        String mapped = mapSegment(seg.toString(), rand, segMap);
        if (mapped == null) return null;
        out.append(mapped).append(';');
        String newDesc = out.toString();
        // 等长校验（字节级）：新串 MUTF-8 字节数必须与原串一致
        if (utf8Len(newDesc) != utf8Len(desc)) return null;
        return newDesc;
    }

    /**
     * 段映射：len 个 ASCII → floor(len/3) 个卢恩 + len%3 个随机小写字母。
     * 段级缓存：同段名（如 "com"）全局同一结果 → 包结构保留 + 点分名同步。
     */
    private static String mapSegment(String seg, Random rand, Map<String, String> segMap) {
        String cached = segMap.get(seg);
        if (cached != null) return cached;
        if (seg.length() > MAX_STR_CHARS - 2) return null; // 防超长
        StringBuilder sb = new StringBuilder(seg.length() + 8);
        int full = seg.length() / 3;
        for (int i = 0; i < full; i++) {
            sb.append(RUNES[rand.nextInt(RUNES.length)]);
        }
        for (int i = 0; i < seg.length() % 3; i++) {
            sb.append((char) ('a' + rand.nextInt(26)));
        }
        if (sb.length() == 0) return null;
        String mapped = sb.toString();
        segMap.put(seg, mapped);
        return mapped;
    }

    /** 纯名字（方法名）：整体做等长段映射，无结构符 */
    private static String mapPlainName(String name, Random rand, Map<String, String> segMap) {
        String cached = segMap.get(name);
        if (cached != null) return cached;
        return mapSegment(name, rand, segMap);
    }

    // ==================== DEX 结构解析（pass 1） ====================

    private static void scanClassDefs(byte[] dex, Set<String> defined,
                                      Set<String> nativeClasses,
                                      Map<String, Boolean> methodUnsafe) {
        try {
            int strSize = u4(dex, 0x38), strOff = u4(dex, 0x3C);
            int typeSize = u4(dex, 0x40), typeOff = u4(dex, 0x44);
            int mthSize = u4(dex, 0x58), mthOff = u4(dex, 0x5C);
            int clsSize = u4(dex, 0x60), clsOff = u4(dex, 0x64);

            // class_def → 自己定义的类描述符
            int[] clsTypeIdx = new int[clsSize];
            int[] clsDataOff = new int[clsSize];
            for (int i = 0; i < clsSize; i++) {
                int base = clsOff + i * 32;
                clsTypeIdx[i] = u4(dex, base);
                clsDataOff[i] = u4(dex, base + 24); // class_data_off
            }
            // type_idx → descriptor string
            String[] typeDesc = new String[typeSize];
            for (int i = 0; i < typeSize; i++) {
                int descIdx = u4(dex, typeOff + i * 4);
                typeDesc[i] = dexString(dex, strOff, descIdx);
            }

            // method name 解析（供 flags 统计）
            String[] mthName = new String[mthSize];
            for (int i = 0; i < mthSize; i++) {
                int nameIdx = u4(dex, mthOff + i * 8 + 4);
                mthName[i] = dexString(dex, strOff, nameIdx);
            }

            for (int i = 0; i < clsSize; i++) {
                String desc = clsTypeIdx[i] < typeSize ? typeDesc[clsTypeIdx[i]] : null;
                if (desc == null) continue;
                defined.add(desc);
                int dataOff = clsDataOff[i];
                if (dataOff == 0) continue;
                scanClassData(dex, dataOff, mthName, nativeClasses, methodUnsafe, desc);
            }
        } catch (Throwable ignored) {
            // 解析失败（异常 DEX）静默跳过，改名流程对该 DEX 无操作
        }
    }

    private static void scanClassData(byte[] dex, int off, String[] mthName,
                                      Set<String> nativeClasses,
                                      Map<String, Boolean> methodUnsafe,
                                      String desc) {
        int[] p = {off};
        int sf = uleb(dex, p);
        int inf = uleb(dex, p);
        int dm = uleb(dex, p);
        int vm = uleb(dex, p);
        // encoded_field 跳过
        for (int i = 0; i < sf + inf; i++) {
            uleb(dex, p); // field_idx_diff
            uleb(dex, p); // access_flags
        }
        boolean nativeFound = false;
        // direct + virtual methods
        for (int k = 0; k < 2; k++) {
            int count = k == 0 ? dm : vm;
            int prevIdx = 0;
            for (int i = 0; i < count; i++) {
                int idxDiff = uleb(dex, p);
                int flags = uleb(dex, p);
                uleb(dex, p); // code_off
                int idx = prevIdx + idxDiff;
                prevIdx = idx;
                String name = idx < mthName.length ? mthName[idx] : null;
                if (name != null) {
                    boolean privateUse = (flags & 0x02) != 0; // ACC_PRIVATE
                    if (!privateUse) {
                        methodUnsafe.put(name, Boolean.TRUE);
                    } else if (!methodUnsafe.containsKey(name)) {
                        methodUnsafe.put(name, Boolean.FALSE);
                    }
                }
                if ((flags & 0x100) != 0) nativeFound = true; // ACC_NATIVE
            }
        }
        if (nativeFound) nativeClasses.add(desc);
    }

    // ==================== DEX 改写（pass 2） ====================

    /**
     * 原地改写 string pool：命中 classMap（描述符/点分名）或 methodMap 的条目等长替换。
     * 返回 [renamed, skippedLong]。改写后重算 SHA-1 signature + adler32 checksum。
     */
    private static int[] applyToDex(byte[] dex, Result r) throws Exception {
        int strSize = u4(dex, 0x38), strOff = u4(dex, 0x3C);
        // 点分全名映射（Class.forName 字符串同步）
        Map<String, String> dotted = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : r.classMap.entrySet()) {
            dotted.put(toDotted(e.getKey()), toDotted(e.getValue()));
        }
        int renamed = 0, skipped = 0;
        for (int i = 0; i < strSize; i++) {
            int dataOff = u4(dex, strOff + i * 4);
            if (dataOff <= 0 || dataOff >= dex.length) continue;
            int[] p = {dataOff};
            int size = uleb(dex, p);
            if (size <= 0) continue;
            if (size > MAX_STR_CHARS) { skipped++; continue; }
            // 找 0x00 终止
            int start = p[0];
            int end = start;
            while (end < dex.length && dex[end] != 0) end++;
            int bytes = end - start;
            if (bytes != size) {
                // 非 ASCII（MUTF-8 多字节）→ 等长数学不适用，跳过
                skipped++;
                continue;
            }
            String s = new String(dex, start, bytes, StandardCharsets.US_ASCII);
            String t = r.classMap.get(s);
            if (t == null) t = dotted.get(s);
            if (t == null && !r.methodMap.isEmpty()) t = r.methodMap.get(s);
            if (t == null) continue;
            byte[] enc = t.getBytes(StandardCharsets.UTF_8); // MUTF-8 与 UTF-8 在 BMP 非 null 一致
            if (enc.length != bytes) continue; // 等长硬校验（理论上必成立）
            System.arraycopy(enc, 0, dex, start, bytes);
            renamed++;
        }
        if (renamed > 0) {
            recomputeChecksum(dex);
        }
        return new int[]{renamed, skipped};
    }

    /** 重算 header：SHA-1 signature（[32:]）与 adler32 checksum（[12:]，排除 magic+checksum 字段） */
    private static void recomputeChecksum(byte[] dex) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(dex, 32, dex.length - 32);
        byte[] sig = sha1.digest();
        System.arraycopy(sig, 0, dex, 12, 20);
        Adler32 adler = new Adler32();
        adler.update(dex, 12, dex.length - 12);
        long v = adler.getValue();
        dex[8] = (byte) v;                    // 小端（DEX 多字节字段统一 LE）
        dex[9] = (byte) (v >>> 8);
        dex[10] = (byte) (v >>> 16);
        dex[11] = (byte) (v >>> 24);
    }

    // ==================== 工具 ====================

    private static String toDotted(String desc) {
        if (!desc.startsWith("L") || !desc.endsWith(";")) return desc;
        return desc.substring(1, desc.length() - 1).replace('/', '.');
    }

    private static boolean isAsciiIdent(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '$')) return false;
        }
        return !s.isEmpty();
    }

    private static int utf8Len(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 0) n += 2;
            else if (c < 0x80) n += 1;
            else if (c < 0x800) n += 2;
            else n += 3;
        }
        return n;
    }

    /** DEX 多字节字段为小端（endian_tag 0x12345678 的字节序即 LE） */
    private static int u4(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    private static int uleb(byte[] b, int[] p) {
        int result = 0, shift = 0, cur = p[0];
        while (shift < 35) {
            if (cur >= b.length) break; // 异常 DEX 防越界
            byte by = b[cur++];
            result |= (by & 0x7F) << shift;
            shift += 7;
            if ((by & 0x80) == 0) break;
        }
        p[0] = cur;
        return result;
    }

    /** 读 string_ids[idx] 指向的字符串（仅 ASCII 场景安全，其他返回原始近似） */
    private static String dexString(byte[] dex, int strOff, int idx) {
        try {
            int dataOff = u4(dex, strOff + idx * 4);
            int[] p = {dataOff};
            int size = uleb(dex, p);
            if (size <= 0 || size > 4096) return null;
            int start = p[0];
            int end = start;
            while (end < dex.length && dex[end] != 0) end++;
            if (end - start == size) {
                return new String(dex, start, size, StandardCharsets.US_ASCII);
            }
            return new String(dex, start, end - start, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return null;
        }
    }
}
