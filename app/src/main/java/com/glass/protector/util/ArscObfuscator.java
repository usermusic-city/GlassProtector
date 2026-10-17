package com.glass.protector.util;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * resources.arsc / AndroidManifest 资源混淆器（AndResGuard 风格，等长原地替换）。
 * <p>
 * 做三件事：
 * 1. 全局字符串池：把 "res/..." 资源文件路径等长随机化（仅当 zip 中真实存在同名条目）
 * 2. package 的 typeStrings / keyStrings 池：type 名与 entry 名等长随机化
 * 3. manifest 字符串池：按同一映射同步替换 "res/" 路径
 * <p>
 * 等长原地替换的意义：chunk size、字符串偏移表、stylesStart 全部保持不变，
 * 不需要重建 chunk 树，级联风险为零。混淆后 aapt2 dump 资源名全部乱码，
 * getIdentifier() 动态查找失效（与 AndResGuard 一致的已知代价），
 * 编译期整数 ID 引用不受影响。
 */
final class ArscObfuscator {

    /** 字符串池 chunk 类型 */
    private static final int CHUNK_STRING_POOL = 0x0001;
    /** arsc 表头 chunk 类型 */
    private static final int CHUNK_TABLE = 0x0002;
    /** package chunk 类型 */
    private static final int CHUNK_PACKAGE = 0x0200;
    /** UTF-8 编码 flag */
    private static final int UTF8_FLAG = 0x100;

    private ArscObfuscator() {
    }

    /** 混淆结果：新 arsc / 新 manifest / 路径映射 / 统计 */
    static final class Result {
        final byte[] arsc;
        final byte[] manifest;
        /** 原路径 → 混淆路径（等长） */
        final Map<String, String> pathMap;
        final int obfPaths;
        final int obfTypeNames;
        final int obfKeyNames;

        Result(byte[] arsc, byte[] manifest, Map<String, String> pathMap,
               int obfPaths, int obfTypeNames, int obfKeyNames) {
            this.arsc = arsc;
            this.manifest = manifest;
            this.pathMap = pathMap;
            this.obfPaths = obfPaths;
            this.obfTypeNames = obfTypeNames;
            this.obfKeyNames = obfKeyNames;
        }
    }

    /**
     * 混淆入口。
     *
     * @param arsc       原始 resources.arsc 字节
     * @param manifest   即将写入产物的二进制 manifest 字节
     * @param zipEntries APK 内全部条目名（用于确认路径真实存在，避免误伤普通字符串）
     */
    static Result obfuscate(byte[] arsc, byte[] manifest, Set<String> zipEntries) {
        byte[] a = arsc.clone();
        Random rng = new Random();
        Set<String> usedPaths = new HashSet<>();
        Map<String, String> pathMap = new HashMap<>();

        // ---- 1. arsc：全局池（res/ 路径）----
        int obfPaths = 0;
        int off = u16(a, 2) == 0 ? 12 : u16(a, 2); // ResTable_header.headerSize（=12）
        boolean seenPackage = false;
        int obfTypeNames = 0, obfKeyNames = 0;
        while (off + 8 <= a.length) {
            int ctype = u16(a, off);
            long csize = u32(a, off + 4);
            if (csize <= 0 || off + csize > a.length) {
                break; // 容错：结构异常直接停止
            }
            if (ctype == CHUNK_STRING_POOL && !seenPackage) {
                obfPaths += obfuscateGlobalPool(a, off, zipEntries, pathMap, usedPaths, rng);
            } else if (ctype == CHUNK_PACKAGE) {
                // package header：8(header)+4(id)+256(name)+4(typeStrings)+4(last)+4(keyStrings)+4(last)
                int typeStringsOff = (int) u32(a, off + 268);
                int keyStringsOff = (int) u32(a, off + 276);
                if (typeStringsOff > 0 && typeStringsOff < csize) {
                    obfTypeNames += obfuscateNamePool(a, off + typeStringsOff,
                            new HashSet<String>(), rng);
                }
                if (keyStringsOff > 0 && keyStringsOff < csize) {
                    obfKeyNames += obfuscateNamePool(a, off + keyStringsOff,
                            new HashSet<String>(), rng);
                }
                seenPackage = true;
            }
            off += (int) csize;
        }

        // ---- 2. manifest：按映射同步替换 res/ 路径 ----
        byte[] m = manifest;
        if (!pathMap.isEmpty() && m != null && m.length > 8) {
            m = m.clone();
            int mHeaderSize = u16(m, 2);
            if (mHeaderSize >= 8 && u16(m, mHeaderSize) == CHUNK_STRING_POOL) {
                syncManifestPool(m, mHeaderSize, pathMap);
            }
        }
        return new Result(a, m, pathMap, obfPaths, obfTypeNames, obfKeyNames);
    }

    /**
     * 全局字符串池：混淆 "res/" 开头且 zip 真实存在的路径。
     * 返回替换数，映射写入 pathMap。
     */
    private static int obfuscateGlobalPool(byte[] d, int poolOff, Set<String> zipEntries,
                                           Map<String, String> pathMap,
                                           Set<String> usedPaths, Random rng) {
        int count = (int) u32(d, poolOff + 8);
        int flags = (int) u32(d, poolOff + 16);
        boolean utf8 = (flags & UTF8_FLAG) != 0;
        int stringsStart = (int) u32(d, poolOff + 20);
        int headerSize = u16(d, poolOff + 2);
        int replaced = 0;
        for (int i = 0; i < count; i++) {
            int strOff = (int) u32(d, poolOff + headerSize + 4 * i);
            int p = poolOff + stringsStart + strOff;
            String s = readString(d, p, utf8);
            if (s == null || !s.startsWith("res/") || !zipEntries.contains(s)) {
                continue; // 只动真实存在的资源路径
            }
            String obf = randomizePath(s, usedPaths, rng);
            if (writeString(d, p, utf8, obf)) {
                pathMap.put(s, obf);
                usedPaths.add(obf);
                replaced++;
            }
        }
        return replaced;
    }

    /** type / key 字符串池：全部名称等长随机化（池内唯一） */
    private static int obfuscateNamePool(byte[] d, int poolOff, Set<String> used, Random rng) {
        int count = (int) u32(d, poolOff + 8);
        int flags = (int) u32(d, poolOff + 16);
        boolean utf8 = (flags & UTF8_FLAG) != 0;
        int stringsStart = (int) u32(d, poolOff + 20);
        int headerSize = u16(d, poolOff + 2);
        int replaced = 0;
        for (int i = 0; i < count; i++) {
            int strOff = (int) u32(d, poolOff + headerSize + 4 * i);
            int p = poolOff + stringsStart + strOff;
            String s = readString(d, p, utf8);
            if (s == null || s.isEmpty()) {
                continue;
            }
            String obf = randomizeName(s, used, rng);
            if (!obf.equals(s) && writeString(d, p, utf8, obf)) {
                used.add(obf);
                replaced++;
            }
        }
        return replaced;
    }

    /** manifest 字符串池：按映射同步替换 */
    private static void syncManifestPool(byte[] d, int poolOff, Map<String, String> pathMap) {
        int count = (int) u32(d, poolOff + 8);
        int flags = (int) u32(d, poolOff + 16);
        boolean utf8 = (flags & UTF8_FLAG) != 0;
        int stringsStart = (int) u32(d, poolOff + 20);
        int headerSize = u16(d, poolOff + 2);
        for (int i = 0; i < count; i++) {
            int strOff = (int) u32(d, poolOff + headerSize + 4 * i);
            int p = poolOff + stringsStart + strOff;
            String s = readString(d, p, utf8);
            if (s == null) {
                continue;
            }
            String mapped = pathMap.get(s);
            if (mapped != null) {
                writeString(d, p, utf8, mapped);
            }
        }
    }

    // ---------------- 字符串池读写 ----------------

    /**
     * 读取池内字符串（p 指向长度字段起点），返回解码字符串；失败返回 null。
     */
    private static String readString(byte[] d, int p, boolean utf8) {
        try {
            if (utf8) {
                int lenChars = d[p] & 0xFF;
                int q = p + 1;
                if ((lenChars & 0x80) != 0) {
                    lenChars = ((lenChars & 0x7F) << 8) | (d[q] & 0xFF);
                    q++;
                }
                int lenBytes = d[q] & 0xFF;
                q++;
                if ((lenBytes & 0x80) != 0) {
                    lenBytes = ((lenBytes & 0x7F) << 8) | (d[q] & 0xFF);
                    q++;
                }
                return new String(d, q, lenBytes, StandardCharsets.UTF_8);
            } else {
                int len = u16(d, p);
                int q = p + 2;
                if ((len & 0x8000) != 0) {
                    len = ((len & 0x7FFF) << 16) | u16(d, q);
                    q += 2;
                }
                return new String(d, q, len * 2, StandardCharsets.UTF_16LE);
            }
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 等长原地写回字符串（长度字段不动，只覆写数据区）。
     * 仅当新字符串与原字符串字节数完全一致时写入，否则拒绝（安全兜底）。
     */
    private static boolean writeString(byte[] d, int p, boolean utf8, String s) {
        try {
            if (utf8) {
                int lenChars = d[p] & 0xFF;
                int q = p + 1;
                if ((lenChars & 0x80) != 0) {
                    lenChars = ((lenChars & 0x7F) << 8) | (d[q] & 0xFF);
                    q++;
                }
                int lenBytes = d[q] & 0xFF;
                q++;
                if ((lenBytes & 0x80) != 0) {
                    lenBytes = ((lenBytes & 0x7F) << 8) | (d[q] & 0xFF);
                    q++;
                }
                byte[] nb = s.getBytes(StandardCharsets.UTF_8);
                if (nb.length != lenBytes || s.length() != lenChars) {
                    return false; // 不等长，拒绝写入
                }
                System.arraycopy(nb, 0, d, q, nb.length);
                return true;
            } else {
                int len = u16(d, p);
                int q = p + 2;
                if ((len & 0x8000) != 0) {
                    len = ((len & 0x7FFF) << 16) | u16(d, q);
                    q += 2;
                }
                byte[] nb = s.getBytes(StandardCharsets.UTF_16LE);
                if (s.length() != len || nb.length != len * 2) {
                    return false; // 不等长，拒绝写入
                }
                System.arraycopy(nb, 0, d, q, nb.length);
                return true;
            }
        } catch (Throwable t) {
            return false;
        }
    }

    // ---------------- 混淆规则 ----------------

    /** 路径混淆：保持 '/' '.' '-' 位置，其余字符随机 [a-z]，全局唯一 */
    private static String randomizePath(String s, Set<String> used, Random rng) {
        for (int retry = 0; retry < 32; retry++) {
            char[] cs = s.toCharArray();
            for (int i = 0; i < cs.length; i++) {
                char c = cs[i];
                if (c != '/' && c != '.' && c != '-') {
                    cs[i] = (char) ('a' + rng.nextInt(26));
                }
            }
            String cand = new String(cs);
            if (!used.contains(cand)) {
                return cand;
            }
        }
        return s; // 极小概率全部撞车：保持原名（安全降级）
    }

    /** 名称混淆：保持 '-' '_' '.' 位置，字母数字随机 [a-z]，池内唯一 */
    private static String randomizeName(String s, Set<String> used, Random rng) {
        for (int retry = 0; retry < 32; retry++) {
            char[] cs = s.toCharArray();
            for (int i = 0; i < cs.length; i++) {
                char c = cs[i];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
                    cs[i] = (char) ('a' + rng.nextInt(26));
                }
            }
            String cand = new String(cs);
            if (!used.contains(cand)) {
                return cand;
            }
        }
        return s; // 撞车降级：保持原名
    }

    // ---------------- 基础读取 ----------------

    private static int u16(byte[] d, int o) {
        return (d[o] & 0xFF) | ((d[o + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] d, int o) {
        return (d[o] & 0xFFL) | ((d[o + 1] & 0xFFL) << 8)
                | ((d[o + 2] & 0xFFL) << 16) | ((d[o + 3] & 0xFFL) << 24);
    }
}
