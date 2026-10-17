package com.luoye.dpt.util;

import com.luoye.dpt.config.Const;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.FileHeader;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.CompressionMethod;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;
import java.util.zip.CheckedOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class ZipUtils {
    private static final List<String> defaultStoreList = Arrays.asList(
            "assets/" + Const.KEY_SHELL_CONFIG_STORE_NAME,
            "assets/" + Const.KEY_DEXES_STORE_NAME,
            "assets/" + Const.KEY_CODE_ITEM_STORE_NAME
    );

    private static final List<String> biggerFileList = Arrays.asList(
            "assets/" + Const.KEY_CODE_ITEM_STORE_NAME
    );

    private static final String META_INF_NAME = "META-INF";

    /**
     * Signature files under META-INF must be dropped before re-sign,
     * but META-INF/services (ServiceLoader) and other resources must be kept.
     */
    private static boolean isSignatureMetaInfFile(String entryName) {
        String name = entryName.replace('\\', '/');
        int slash = name.lastIndexOf('/');
        String fileName = slash >= 0 ? name.substring(slash + 1) : name;
        String upper = fileName.toUpperCase(Locale.US);
        return upper.equals("MANIFEST.MF")
                || upper.endsWith(".SF")
                || upper.endsWith(".RSA")
                || upper.endsWith(".DSA")
                || upper.endsWith(".EC");
    }

    /**
     * don not compress file list
     */
    private static final List<String> doNotCompress = new ArrayList<>(defaultStoreList);
    /**
     * when unzip apk on window, the file name maybe conflict.
     * this is fix it
     */
    private static final Map<String, String> resConflictFiles = new HashMap<>();
    private static final HashMap<String, CompressionMethod> compressedLevelMap = new HashMap<>();
    private static final String RENAME_SUFFIX = ".renamed";

    /**
     * Read asset file from .jar
     */
    public static void readResourceFromRuntime(String resourcePath, String distPath) throws IOException {
        InputStream inputStream = ZipUtils.class.getClassLoader()
                                                .getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new IOException("cannot get resource:" + resourcePath);
        }
        File distFile = new File(distPath);
        if (!distFile.getParentFile()
                     .exists()) {
            distFile.getParentFile()
                    .mkdirs();
        }
        try (BufferedInputStream in = new BufferedInputStream(inputStream);
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(distFile))) {
            int len = -1;
            byte[] b = new byte[1024];
            while ((len = in.read(b)) != -1) {
                out.write(b, 0, len);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void setCompressionMethod(String fileName,ZipParameters zipParameters) {
        if (compressedLevelMap.containsKey(fileName)) {
            zipParameters.setCompressionMethod(compressedLevelMap.get(fileName));
        }
        if(defaultStoreList.contains(fileName)) {
            zipParameters.setCompressionMethod(CompressionMethod.STORE);
        }
    }

    private static void addEntry(ZipFile zipFile,String rootDir,File parent) throws IOException{
        ZipParameters zipParameters = new ZipParameters();
        if(parent.isDirectory()) {
            File[] list = parent.listFiles();
            if(list == null) {
                return;
            }
            if (list.length > 0) {
                for (File f : list) {
                    if (f.isDirectory()) {
                        addEntry(zipFile, rootDir, f);
                    } else {
                        String entryName = f.getAbsolutePath().replace(rootDir,"").substring(1);
                        entryName = entryName.replaceAll("\\\\","/");
                        File entryFile = new File(entryName);
                        zipParameters.setRootFolderNameInZip(entryFile.getParent());
                        setCompressionMethod(entryName, zipParameters);
                        zipFile.addFile(f.getAbsoluteFile(), zipParameters);
                    }
                }
            } else {
                String entryName = parent.getAbsolutePath().replace(rootDir,"").substring(1);
                entryName = entryName.replaceAll("\\\\","/");
                File entryFile = new File(entryName);
                zipParameters.setRootFolderNameInZip(entryFile.getParent());
                setCompressionMethod(entryName, zipParameters);
                zipFile.addFolder(parent, zipParameters);
            }
        }
        else {
            String entryName = parent.getAbsolutePath().replace(rootDir,"").substring(1);
            entryName = entryName.replaceAll("\\\\","/");
            File entryFile = new File(entryName);
            zipParameters.setRootFolderNameInZip(entryFile.getParent());
            setCompressionMethod(entryName, zipParameters);
            zipFile.addFile(parent, zipParameters);
        }
    }
    /**
     * Compress files to apk
     */
    public static void compressToApk(String srcDir, String destFile) {
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(destFile);
            File dir = new File(srcDir);
            addEntry(zipFile, dir.getAbsolutePath(), dir);
            List<FileHeader> fileHeaders = zipFile.getFileHeaders();
            for (FileHeader fileHeader : fileHeaders) {
                String fileName = fileHeader.getFileName();
                if (fileName.contains(RENAME_SUFFIX)) {
                    String newFileName = fileName.replaceAll(RENAME_SUFFIX + "\\d+$", "");
                    zipFile.renameFile(fileHeader, newFileName);
                    LogUtils.noisy("compress file name restore: %s -> %s", fileName, newFileName);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(zipFile);
        }
    }

    private static void writeZipEntry(ZipInputStream zipInputStream, String targetFilePath) {
        FileOutputStream fos = null;
        try {
            File targetFile = new File(targetFilePath);
            if (!targetFile.getParentFile()
                           .exists()) {
                targetFile.getParentFile()
                          .mkdirs();
            }
            fos = new FileOutputStream(targetFile);
            int len = 0;
            byte[] buf = new byte[1024];
            while ((len = zipInputStream.read(buf)) != -1) {
                fos.write(buf, 0, len);
            }
        } catch (IOException e) {
            LogUtils.error("writeZipEntry err = %s", e);
        } finally {
            IoUtils.close(fos);
        }
    }

    /**
     * Unzip apk
     */
    public static void extractAPK(String zipFilePath, String destDir) {
        ZipInputStream zipInputStream = null;
        Map<String, Integer> zipEntryNameMap = new HashMap<>();
        try {
            zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry zipEntry = null;

            while ((zipEntry = zipInputStream.getNextEntry()) != null) {

                String zipEntryName = zipEntry.getName();

                CompressionMethod compressionMethod = CompressionMethod.getCompressionMethodFromCode(zipEntry.getMethod());

                compressedLevelMap.put(zipEntryName, compressionMethod);

                String lowerCase = zipEntryName.toLowerCase(Locale.US);
                String finalFileName = zipEntryName;
                if (zipEntryNameMap.get(lowerCase) != null) {
                    int num = zipEntryNameMap.get(lowerCase) + 1;
                    finalFileName = zipEntryName + RENAME_SUFFIX + num;
                    zipEntryNameMap.put(lowerCase, num);
                } else {
                    zipEntryNameMap.put(lowerCase, 0);
                }
                writeZipEntry(zipInputStream, destDir + File.separator + finalFileName);

            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(zipInputStream);
        }
    }

    /**
     * Unzip a file
     */
    public static void extractFile(String zipFilePath, String fileName, String destDir) {
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(zipFilePath);
            FileHeader fileHeader = zipFile.getFileHeader(fileName);
            zipFile.extractFile(fileHeader, destDir);
        } catch (ZipException e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(zipFile);
        }
    }


    /**
     * Compress to common zip file
     */
    public static void compress(List<File> files, String destFile, Map<String, CompressionMethod> rulesMap) {
        if (files == null) {
            return;
        }
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(destFile);
            for (File f : files) {
                ZipParameters zipParameters = new ZipParameters();
                if(rulesMap != null) {
                    for (String key : rulesMap.keySet()) {
                        if (f.getName().matches(key)) {
                            zipParameters.setCompressionMethod(rulesMap.get(key));
                            break;
                        }
                    }
                }
                if (f.isDirectory()) {
                    zipFile.addFolder(f.getAbsoluteFile(), zipParameters);
                } else {
                    zipFile.addFile(f.getAbsoluteFile(), zipParameters);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(zipFile);
        }
    }

    /**
     * unzip
     *
     * @param zipPath apk/aab path
     * @param dirPath unzip dir path
     */
    public static void unZip(String zipPath, String dirPath) {
        java.util.zip.ZipFile zipFile = null;
        try {
            File zip = new File(zipPath);
            File dir = new File(dirPath);
            if (dir.exists()) {
                FileUtils.deleteRecurse(dir);
            }
            zipFile = new java.util.zip.ZipFile(zip);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry zipEntry = entries.nextElement();
                String name = zipEntry.getName();
                if (name.startsWith("META-INF/") && isSignatureMetaInfFile(name)) {
                    continue;
                }
                if (!zipEntry.isDirectory()) {
                    File file = new File(dir, name);
                    if (file.exists()) {
                        String fileName = file.getName();
                        int count = 1;
                        for (String v : resConflictFiles.values()) {
                            if (v.equalsIgnoreCase(fileName)) {
                                count++;
                            }
                        }
                        String rename;
                        do {
                            rename = count + fileName;
                            file = new File(file.getParentFile(), rename);
                            count++;
                        } while (file.exists());
                        resConflictFiles.put(rename, fileName);
                    }
                    if (!file.getParentFile().exists()) {
                        file.getParentFile().mkdirs();
                    }
                    if (zipEntry.getCompressedSize() == zipEntry.getSize()) {
                        doNotCompress.add(file.getAbsolutePath().replace(dir.getAbsolutePath() + File.separator, ""));
                    }
                    try (FileOutputStream fos = new FileOutputStream(file);
                         InputStream is = zipFile.getInputStream(zipEntry)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = is.read(buffer)) != -1) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(zipFile);
        }
    }

    /**
     * zip apk/aab
     *
     * @param dirPath apk/aab unzip dir path
     * @param zipPath zip apk path
     */
    public static void zip(String dirPath, String zipPath, boolean smaller) {
        if(smaller) {
            doNotCompress.removeAll(biggerFileList);
        }
        ZipOutputStream zos = null;
        try {
            File zip = new File(zipPath);
            if(zip.exists()) {
                zip.delete();
            }
            CheckedOutputStream cos = new CheckedOutputStream(Files.newOutputStream(zip.toPath()), new CRC32());
            zos = new ZipOutputStream(cos);
            for (int i = 0; i < doNotCompress.size(); i++) {
                String check = doNotCompress.get(i);
                check = check.replaceAll("/", Matcher.quoteReplacement(File.separator));
                doNotCompress.set(i, check);
            }
            File dir = new File(dirPath);
            compress(dir, zos, "", doNotCompress, resConflictFiles);
            zos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            IoUtils.close(zos);
        }
    }

    private static void compress(File srcFile, ZipOutputStream zos, String basePath,
                                 List<String> doNotCompress, Map<String, String> resConflictFiles) throws Exception {
        if (srcFile.isDirectory()) {
            compressDir(srcFile, zos, basePath, doNotCompress, resConflictFiles);
        } else {
            compressFile(srcFile, zos, basePath, doNotCompress, resConflictFiles);
        }
    }

    private static void compressDir(File dir, ZipOutputStream zos, String basePath,
                                    List<String> doNotCompress, Map<String, String> resConflictFiles) throws Exception {
        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }
        if (files.length == 0) {
            String entryName = basePath + dir.getName() + "/";
            ZipEntry entry = new ZipEntry(entryName);
            zos.putNextEntry(entry);
            zos.closeEntry();
        }
        for (File file : files) {
            compress(file, zos, basePath + dir.getName() + "/", doNotCompress, resConflictFiles);
        }
    }

    private static void compressFile(File file, ZipOutputStream zos, String dir,
                                     List<String> doNotCompress, Map<String, String> resConflictFiles) throws Exception {
        String fileName = file.getName();
        if (resConflictFiles.containsKey(fileName)) {
            fileName = resConflictFiles.get(fileName);
        }
        String dirName = dir + fileName;
        // Keep META-INF/services for ServiceLoader (e.g. kotlinx.coroutines Main dispatcher),
        // but exclude old signature files to avoid resign conflicts.
        if (dirName.contains(META_INF_NAME) && isSignatureMetaInfFile(dirName)) {
            return;
        }
        String[] dirNameNew = dirName.split("/");

        StringBuilder buffer = new StringBuilder();

        if (dirNameNew.length > 1) {
            for (int i = 1; i < dirNameNew.length; i++) {
                buffer.append("/");
                buffer.append(dirNameNew[i]);

            }
        } else {
            buffer.append("/");
        }

        ZipEntry entry = new ZipEntry(buffer.substring(1));
        String rawPath = file.getAbsolutePath();
        int index = rawPath.indexOf(dirNameNew[0]);
        if (index != -1 && doNotCompress.contains(rawPath.substring(index + 1 + dirNameNew[0].length()))) {
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(file.length());
            entry.setCrc(calFileCRC32(file));
        }
        zos.putNextEntry(entry);
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            int count;
            byte[] data = new byte[1024];
            while ((count = bis.read(data, 0, 1024)) != -1) {
                zos.write(data, 0, count);
            }
        }
        zos.closeEntry();
    }

    private static long calFileCRC32(File file) throws IOException {
        try (FileInputStream fi = new FileInputStream(file);
             CheckedInputStream checksum = new CheckedInputStream(fi, new CRC32());
             BufferedInputStream in = new BufferedInputStream(checksum)) {
            while (in.read() != -1);
            return checksum.getChecksum().getValue();
        }
    }
}
