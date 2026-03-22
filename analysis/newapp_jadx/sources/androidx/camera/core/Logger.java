package androidx.camera.core;

import android.os.Build;
import android.util.Log;
import androidx.annotation.IntRange;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;

@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes.dex */
public final class Logger {
    private static final int DEFAULT_MIN_LOG_LEVEL = 3;
    private static final int MAX_TAG_LENGTH = 23;
    private static int sMinLogLevel = 3;

    private Logger() {
    }

    /* renamed from: d */
    public static void m123d(@NonNull String str, @NonNull String str2) {
        m124d(str, str2, null);
    }

    /* renamed from: e */
    public static void m125e(@NonNull String str, @NonNull String str2) {
        m126e(str, str2, null);
    }

    /* renamed from: i */
    public static void m127i(@NonNull String str, @NonNull String str2) {
        m128i(str, str2, null);
    }

    public static boolean isDebugEnabled(@NonNull String str) {
        return sMinLogLevel <= 3 || Log.isLoggable(truncateTag(str), 3);
    }

    public static boolean isErrorEnabled(@NonNull String str) {
        return sMinLogLevel <= 6 || Log.isLoggable(truncateTag(str), 6);
    }

    public static boolean isInfoEnabled(@NonNull String str) {
        return sMinLogLevel <= 4 || Log.isLoggable(truncateTag(str), 4);
    }

    public static boolean isWarnEnabled(@NonNull String str) {
        return sMinLogLevel <= 5 || Log.isLoggable(truncateTag(str), 5);
    }

    public static void setMinLogLevel(@IntRange(from = 3, m111to = 6) int i2) {
        sMinLogLevel = i2;
    }

    @NonNull
    private static String truncateTag(@NonNull String str) {
        return (23 >= str.length() || Build.VERSION.SDK_INT >= 24) ? str : str.substring(0, 23);
    }

    /* renamed from: w */
    public static void m129w(@NonNull String str, @NonNull String str2) {
        m130w(str, str2, null);
    }

    /* renamed from: d */
    public static void m124d(@NonNull String str, @NonNull String str2, @Nullable Throwable th) {
        if (isDebugEnabled(str)) {
            truncateTag(str);
        }
    }

    /* renamed from: e */
    public static void m126e(@NonNull String str, @NonNull String str2, @Nullable Throwable th) {
        if (isErrorEnabled(str)) {
            truncateTag(str);
        }
    }

    /* renamed from: i */
    public static void m128i(@NonNull String str, @NonNull String str2, @Nullable Throwable th) {
        if (isInfoEnabled(str)) {
            truncateTag(str);
        }
    }

    /* renamed from: w */
    public static void m130w(@NonNull String str, @NonNull String str2, @Nullable Throwable th) {
        if (isWarnEnabled(str)) {
            truncateTag(str);
        }
    }
}
