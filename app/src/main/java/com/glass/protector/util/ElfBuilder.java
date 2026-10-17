package com.glass.protector.util;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * 手工构造最小化 ELF 共享库（数据容器）。
 * <p>
 * Dex2C 模式：把壳配置 blob 封装进 lib/&lt;abi&gt;/libglass_core.so，
 * 壳运行时优先从 nativeLibraryDir 读取，assets/glass.dat 仅作回退。
 * <p>
 * 产物是结构合法的 ELF（readelf -h/-S 可验证）：
 * ELF64/aarch64 与 ELF32/arm 两种变体，含 .shstrtab/.glass_cfg/.note.glass 节。
 * .glass_cfg 内容布局：ASCII 魔数 "GLCFG1" + 4 字节大端长度 + blob。
 * 壳侧扫描魔数即可取回，无需完整 ELF 解析器。
 */
final class ElfBuilder {

    /** 配置节魔数（壳侧 ShellData 同步扫描） */
    static final byte[] CFG_MAGIC = "GLCFG1".getBytes(StandardCharsets.US_ASCII);

    private static final int ET_DYN = 3;
    private static final int EM_ARM = 40;      // ELF32 arm
    private static final int EM_AARCH64 = 0xB7; // ELF64 aarch64

    private static final int SHT_NULL = 0;
    private static final int SHT_STRTAB = 3;
    private static final int SHT_PROGBITS = 1;
    private static final int SHT_NOTE = 7;

    private ElfBuilder() {
    }

    /** 构造 ELF64 (aarch64) libglass_core.so，内含配置 blob */
    static byte[] buildElf64(byte[] cfgBlob, String note) {
        byte[] shstrtab = buildShstrtab();
        byte[] cfgSection = buildCfgSection(cfgBlob);
        byte[] noteSection = buildNoteSection(note);

        int ehsize = 64;
        int off1 = ehsize;
        int off2 = off1 + shstrtab.length;
        int off3 = off2 + cfgSection.length;
        // 节头表 4 字节对齐
        int shoff = (off3 + noteSection.length + 3) & ~3;

        int shnum = 4;
        int shentsize = 64;

        ByteArrayOutputStream out = new ByteArrayOutputStream(shoff + shnum * shentsize);
        // ---- ELF header (64) ----
        out.write(0x7F); out.write('E'); out.write('L'); out.write('F');
        out.write(2);   // ELFCLASS64
        out.write(1);   // ELFDATA2LSB
        out.write(1);   // EV_CURRENT
        out.write(0);   // ELFOSABI_NONE
        out.write(0);   // ABI version
        pad(out, 7);
        le16(out, ET_DYN);
        le16(out, EM_AARCH64);
        le32(out, 1);          // e_version
        le64(out, 0);          // e_entry
        le64(out, 0);          // e_phoff（无程序头：纯数据容器）
        le64(out, shoff);      // e_shoff
        le32(out, 0);          // e_flags
        le16(out, ehsize);
        le16(out, 56);         // e_phentsize
        le16(out, 0);          // e_phnum
        le16(out, shentsize);
        le16(out, shnum);
        le16(out, 1);          // e_shstrndx → .shstrtab
        // ---- sections ----
        write(out, shstrtab);
        write(out, cfgSection);
        write(out, noteSection);
        pad(out, shoff - out.size());
        // ---- section headers ----
        shdr64(out, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);                 // [0] NULL
        shdr64(out, nameOff(shstrtab, ".shstrtab"), SHT_STRTAB, 0,
                0, off1, shstrtab.length, 0, 0, 1, 0);                 // [1] .shstrtab
        shdr64(out, nameOff(shstrtab, ".glass_cfg"), SHT_PROGBITS, 0x2 /*ALLOC*/,
                0, off2, cfgSection.length, 0, 0, 4, 0);               // [2] .glass_cfg
        shdr64(out, nameOff(shstrtab, ".note.glass"), SHT_NOTE, 0,
                0, off3, noteSection.length, 0, 0, 4, 0);              // [3] .note.glass
        return out.toByteArray();
    }

    /** 构造 ELF32 (arm) libglass_core.so，内含配置 blob */
    static byte[] buildElf32(byte[] cfgBlob, String note) {
        byte[] shstrtab = buildShstrtab();
        byte[] cfgSection = buildCfgSection(cfgBlob);
        byte[] noteSection = buildNoteSection(note);

        int ehsize = 52;
        int off1 = ehsize;
        int off2 = off1 + shstrtab.length;
        int off3 = off2 + cfgSection.length;
        int shoff = (off3 + noteSection.length + 3) & ~3;

        int shnum = 4;
        int shentsize = 40;

        ByteArrayOutputStream out = new ByteArrayOutputStream(shoff + shnum * shentsize);
        // ---- ELF header (52) ----
        out.write(0x7F); out.write('E'); out.write('L'); out.write('F');
        out.write(1);   // ELFCLASS32
        out.write(1);   // ELFDATA2LSB
        out.write(1);   // EV_CURRENT
        out.write(0);   // ELFOSABI_NONE
        out.write(0);   // ABI version
        pad(out, 7);
        le16(out, ET_DYN);
        le16(out, EM_ARM);
        le32(out, 1);
        le32(out, 0);          // e_entry
        le32(out, 0);          // e_phoff
        le32(out, shoff);      // e_shoff
        le32(out, 0);          // e_flags
        le16(out, ehsize);
        le16(out, 32);         // e_phentsize
        le16(out, 0);          // e_phnum
        le16(out, shentsize);
        le16(out, shnum);
        le16(out, 1);          // e_shstrndx
        // ---- sections ----
        write(out, shstrtab);
        write(out, cfgSection);
        write(out, noteSection);
        pad(out, shoff - out.size());
        // ---- section headers ----
        shdr32(out, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);                 // [0] NULL
        shdr32(out, nameOff(shstrtab, ".shstrtab"), SHT_STRTAB, 0,
                0, off1, shstrtab.length, 0, 0, 1, 0);                 // [1] .shstrtab
        shdr32(out, nameOff(shstrtab, ".glass_cfg"), SHT_PROGBITS, 0x2,
                0, off2, cfgSection.length, 0, 0, 4, 0);               // [2] .glass_cfg
        shdr32(out, nameOff(shstrtab, ".note.glass"), SHT_NOTE, 0,
                0, off3, noteSection.length, 0, 0, 4, 0);              // [3] .note.glass
        return out.toByteArray();
    }

    /** .glass_cfg 节内容：魔数 + 4 字节大端长度 + blob */
    private static byte[] buildCfgSection(byte[] cfgBlob) {
        ByteArrayOutputStream s = new ByteArrayOutputStream(6 + 4 + cfgBlob.length);
        write(s, CFG_MAGIC);
        s.write((cfgBlob.length >>> 24) & 0xFF);
        s.write((cfgBlob.length >>> 16) & 0xFF);
        s.write((cfgBlob.length >>> 8) & 0xFF);
        s.write(cfgBlob.length & 0xFF);
        write(s, cfgBlob);
        return s.toByteArray();
    }

    /** .note.glass 节内容：ELF note 格式（namesz/descsz/type + name + desc） */
    private static byte[] buildNoteSection(String note) {
        byte[] name = "Glass\0".getBytes(StandardCharsets.US_ASCII);
        byte[] desc = note.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream s = new ByteArrayOutputStream(12 + name.length + desc.length);
        le32(s, name.length);
        le32(s, desc.length);
        le32(s, 1); // NT_VERSION 风格自定义 type
        write(s, name);
        write(s, desc);
        return s.toByteArray();
    }

    private static byte[] buildShstrtab() {
        // \0.shstrtab\0.glass_cfg\0.note.glass\0
        return ("\u0000.shstrtab\u0000.glass_cfg\u0000.note.glass\u0000")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static int nameOff(byte[] shstrtab, String name) {
        String s = new String(shstrtab, StandardCharsets.US_ASCII);
        return s.indexOf(name);
    }

    // ---------------- 基础写出 ----------------

    private static void shdr64(ByteArrayOutputStream o, int name, int type, long flags,
                               long addr, long offset, long size, int link, int info,
                               long align, long entsize) {
        le32(o, name);
        le32(o, type);
        le64(o, flags);
        le64(o, addr);
        le64(o, offset);
        le64(o, size);
        le32(o, link);
        le32(o, info);
        le64(o, align);
        le64(o, entsize);
    }

    private static void shdr32(ByteArrayOutputStream o, int name, int type, int flags,
                               int addr, int offset, int size, int link, int info,
                               int align, int entsize) {
        le32(o, name);
        le32(o, type);
        le32(o, flags);
        le32(o, addr);
        le32(o, offset);
        le32(o, size);
        le32(o, link);
        le32(o, info);
        le32(o, align);
        le32(o, entsize);
    }

    private static void le16(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >>> 8) & 0xFF);
    }

    private static void le32(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >>> 8) & 0xFF);
        o.write((v >>> 16) & 0xFF);
        o.write((v >>> 24) & 0xFF);
    }

    private static void le64(ByteArrayOutputStream o, long v) {
        le32(o, (int) (v & 0xFFFFFFFFL));
        le32(o, (int) (v >>> 32));
    }

    private static void write(ByteArrayOutputStream o, byte[] data) {
        o.write(data, 0, data.length);
    }

    private static void pad(ByteArrayOutputStream o, int n) {
        for (int i = 0; i < n; i++) o.write(0);
    }
}
