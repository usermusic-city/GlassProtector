package com.glass.protector.util;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * APK文件工具类
 */
public class ApkUtils {

    /**
     * 从Uri获取文件真实路径
     */
    public static String getPathFromUri(Context context, Uri uri) {
        String path = null;
        if ("content".equalsIgnoreCase(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (index >= 0) {
                        String fileName = cursor.getString(index);
                        // 复制到缓存目录
                        File cacheFile = new File(context.getCacheDir(), fileName);
                        try (InputStream is = context.getContentResolver().openInputStream(uri);
                             OutputStream os = new FileOutputStream(cacheFile)) {
                            if (is != null) {
                                byte[] buffer = new byte[8192];
                                int len;
                                while ((len = is.read(buffer)) != -1) {
                                    os.write(buffer, 0, len);
                                }
                                path = cacheFile.getAbsolutePath();
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if ("file".equalsIgnoreCase(uri.getScheme())) {
            path = uri.getPath();
        }
        return path;
    }

    /**
     * 格式化文件大小
     */
    public static String formatFileSize(long size) {
        if (size <= 0) return "0 B";
        final String[] units = {"B", "KB", "MB", "GB"};
        int digitGroups = (int) (Math.log10(size) / Math.log10(1024));
        if (digitGroups >= units.length) digitGroups = units.length - 1;
        return new DecimalFormat("#,##0.##").format(size / Math.pow(1024, digitGroups)) + " " + units[digitGroups];
    }

    /**
     * 确保输出目录存在
     */
    public static void ensureDir(String dirPath) {
        File dir = new File(dirPath);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    /**
     * 复制文件
     */
    public static void copyFile(String src, String dest) throws IOException {
        try (FileInputStream fis = new FileInputStream(src);
             FileOutputStream fos = new FileOutputStream(dest)) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
        }
    }

    /**
     * 检查是否为有效APK文件
     */
    public static boolean isValidApk(String filePath) {
        if (filePath == null) return false;
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) return false;
        if (!filePath.toLowerCase().endsWith(".apk")) return false;
        try (ZipFile zipFile = new ZipFile(file)) {
            return zipFile.getEntry("AndroidManifest.xml") != null;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * 获取默认输出目录
     */
    public static String getDefaultOutputDir() {
        String dir = Environment.getExternalStorageDirectory() + "/GlassProtector/output";
        ensureDir(dir);
        return dir;
    }
}
