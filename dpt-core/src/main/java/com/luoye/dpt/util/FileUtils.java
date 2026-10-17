package com.luoye.dpt.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * 文件工具类 - 从dpt-shell移植，修复了路径处理bug
 */
public class FileUtils {

    /**
     * 获取目录，不存在则创建
     */
    public static File getDir(String parent, String child) {
        File dir = new File(parent, child);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    /**
     * 复制文件
     */
    public static void copyFile(File src, File dest) throws IOException {
        if (!dest.getParentFile().exists()) {
            dest.getParentFile().mkdirs();
        }
        Files.copy(src.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * 复制目录
     */
    public static void copyDir(File srcDir, File destDir) throws IOException {
        if (!destDir.exists()) {
            destDir.mkdirs();
        }
        File[] files = srcDir.listFiles();
        if (files != null) {
            for (File file : files) {
                File destFile = new File(destDir, file.getName());
                if (file.isDirectory()) {
                    copyDir(file, destFile);
                } else {
                    copyFile(file, destFile);
                }
            }
        }
    }

    /**
     * 删除目录
     */
    public static void deleteDir(File dir) {
        if (dir.isDirectory()) {
            File[] children = dir.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteDir(child);
                }
            }
        }
        dir.delete();
    }

    /**
     * 读取文件为字节数组
     */
    public static byte[] readFile(File file) throws IOException {
        byte[] data = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            int offset = 0;
            int read;
            while (offset < data.length && (read = fis.read(data, offset, data.length - offset)) != -1) {
                offset += read;
            }
        }
        return data;
    }

    /**
     * 写入字节数组到文件
     */
    public static void writeFile(File file, byte[] data) throws IOException {
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }

    /**
     * 获取可执行文件路径（修复了原版jar路径解析bug）
     */
    public static String getExecutablePath() {
        try {
            File jarFile = new File(FileUtils.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            return jarFile.getParent();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 格式化文件大小
     */
    public static String formatFileSize(long size) {
        if (size < 1024) return size + " B";
        if (size < 1024 * 1024) return String.format("%.2f KB", size / 1024.0);
        if (size < 1024 * 1024 * 1024) return String.format("%.2f MB", size / (1024.0 * 1024));
        return String.format("%.2f GB", size / (1024.0 * 1024 * 1024));
    }
}
