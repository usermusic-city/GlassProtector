package com.luoye.dpt.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * IO工具类 - 从dpt-shell移植，修复了流关闭bug
 */
public class IoUtils {

    private static final int BUFFER_SIZE = 8192;

    /**
     * 读取输入流全部内容为字节数组
     */
    public static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        copy(is, baos);
        return baos.toByteArray();
    }

    /**
     * 复制输入流到输出流
     */
    public static long copy(InputStream is, OutputStream os) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        long total = 0;
        int read;
        while ((read = is.read(buffer)) != -1) {
            os.write(buffer, 0, read);
            total += read;
        }
        os.flush();
        return total;
    }

    /**
     * 安全关闭流
     */
    public static void closeQuietly(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * 读取输入流为字符串
     */
    public static String readString(InputStream is, String charset) throws IOException {
        return new String(readAll(is), charset);
    }
}
