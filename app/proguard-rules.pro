# GlassProtector ProGuard Rules

# 保留加固相关类
-keep class com.glass.protector.** { *; }
-keep class com.luoye.dpt.** { *; }

# 保留Native方法
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留JNI回调
-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet);
}

# 保留枚举
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# 保留Parcelable
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# 保留Serializable
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# 不优化加固核心代码
-dontoptimize
-dontshrink
