package com.glass.shell;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * 反射工具 + DEX 注入核心。
 * 把解密后的 DEX 的 dexElements 合并进宿主 ClassLoader，
 * 使宿主能加载原 APK 的全部类。
 */
final class DexInjector {

    private DexInjector() {
    }

    /**
     * 将 loader 的 dexElements 合并进 host 的 dexElements 前部。
     * 原理：BaseDexClassLoader.pathList(DexPathList).dexElements(Object[])
     */
    static void inject(ClassLoader host, ClassLoader loader) throws Exception {
        Object hostPathList = getPathList(host);
        Object addPathList = getPathList(loader);
        Object[] hostElems = (Object[]) getField(hostPathList, "dexElements");
        Object[] addElems = (Object[]) getField(addPathList, "dexElements");
        Object[] merged = (Object[]) Array.newInstance(hostElems.getClass().getComponentType(),
                hostElems.length + addElems.length);
        // 解密 dex 放前面优先加载
        System.arraycopy(addElems, 0, merged, 0, addElems.length);
        System.arraycopy(hostElems, 0, merged, addElems.length, hostElems.length);
        setField(hostPathList, "dexElements", merged);
    }

    private static Object getPathList(ClassLoader cl) throws Exception {
        return getField(cl, "pathList");
    }

    static Object getField(Object obj, String name) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(obj);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name + " in " + obj.getClass().getName());
    }

    static void setField(Object obj, String name, Object value) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(obj, value);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name + " in " + obj.getClass().getName());
    }

    static Object call(Object obj, String name, Class<?>[] types, Object... args) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Method m = c.getDeclaredMethod(name, types);
                m.setAccessible(true);
                return m.invoke(obj, args);
            } catch (NoSuchMethodException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchMethodException(name + " in " + obj.getClass().getName());
    }
}
