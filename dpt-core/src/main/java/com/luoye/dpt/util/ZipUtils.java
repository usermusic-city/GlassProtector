package com.luoye.dpt.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * ZIP工具类 - 从dpt-shell移植，修复了大文件压缩bug
 */
public class ZipUtils {

    private static final int BUFFER_SIZE = 8192;

    /**
     * 解压ZIP文件到指定目录
     */
    public static void unzip(String zipPath, String destDir) throws IOException {
        File dest = new File(destDir);
        if (!dest.exists()) {
            dest.mkdirs();
        }
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File outFile = new File(destDir, entry.getName());
                // 修复bug: 防止路径遍历攻击
                if (!outFile.getCanonicalPath().startsWith(dest.getCanonicalPath())) {
                    throw new IOException("Entry is outside of the target dir: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    outFile.mkdirs();
                } else {
                    outFile.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(outFile)) {
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int len;
                        while ((len = zis.read(buffer)) != -1) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
                zis.closeEntry();
            }
        }
    }

    /**
     * 压缩目录为ZIP文件
     */
    public static void zip(String srcDir, String destZip) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(destZip))) {
            File srcFile = new File(srcDir);
            addFileToZip(zos, srcFile, srcFile.getAbsolutePath());
        }
    }

    private static void addFileToZip(ZipOutputStream zos, File file, String basePath) throws IOException {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    addFileToZip(zos, child, basePath);
                }
            }
        } else {
            String entryName = file.getAbsolutePath().substring(basePath.length() + 1);
            // 修复bug: 使用正斜杠，确保跨平台兼容
            entryName = entryName.replace("\\", "/");
            ZipEntry entry = new ZipEntry(entryName);
            zos.putNextEntry(entry);
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    zos.write(buffer, 0, len);
                }
            }
            zos.closeEntry();
        }
    }

    /**
     * 从ZIP中读取单个文件
     */
    public static byte[] readFileFromZip(String zipPath, String entryName) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(entryName)) {
                    return IoUtils.readAll(zis);
                }
                zis.closeEntry();
            }
        }
        return null;
    }

    /**
     * 检查ZIP中是否存在指定文件
     */
    public static boolean containsEntry(String zipPath, String entryName) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(entryName)) {
                    return true;
                }
                zis.closeEntry();
            }
        }
        return false;
    }
}
