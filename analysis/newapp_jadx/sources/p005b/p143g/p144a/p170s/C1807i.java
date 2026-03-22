package p005b.p143g.p144a.p170s;

import android.annotation.TargetApi;
import android.graphics.Bitmap;
import android.os.Looper;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/* renamed from: b.g.a.s.i */
/* loaded from: classes.dex */
public final class C1807i {

    /* renamed from: a */
    public static final char[] f2767a = "0123456789abcdef".toCharArray();

    /* renamed from: b */
    public static final char[] f2768b = new char[64];

    /* renamed from: b.g.a.s.i$a */
    public static /* synthetic */ class a {

        /* renamed from: a */
        public static final /* synthetic */ int[] f2769a;

        static {
            int[] iArr = new int[Bitmap.Config.values().length];
            f2769a = iArr;
            try {
                iArr[Bitmap.Config.ALPHA_8.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f2769a[Bitmap.Config.RGB_565.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f2769a[Bitmap.Config.ARGB_4444.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f2769a[Bitmap.Config.RGBA_F16.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f2769a[Bitmap.Config.ARGB_8888.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
        }
    }

    /* renamed from: a */
    public static void m1144a() {
        if (!m1151h()) {
            throw new IllegalArgumentException("You must call this method on the main thread");
        }
    }

    /* renamed from: b */
    public static boolean m1145b(@Nullable Object obj, @Nullable Object obj2) {
        return obj == null ? obj2 == null : obj.equals(obj2);
    }

    /* renamed from: c */
    public static int m1146c(int i2, int i3, @Nullable Bitmap.Config config) {
        int i4 = i2 * i3;
        if (config == null) {
            config = Bitmap.Config.ARGB_8888;
        }
        int i5 = a.f2769a[config.ordinal()];
        int i6 = 4;
        if (i5 == 1) {
            i6 = 1;
        } else if (i5 == 2 || i5 == 3) {
            i6 = 2;
        } else if (i5 == 4) {
            i6 = 8;
        }
        return i4 * i6;
    }

    @TargetApi(19)
    /* renamed from: d */
    public static int m1147d(@NonNull Bitmap bitmap) {
        if (!bitmap.isRecycled()) {
            try {
                return bitmap.getAllocationByteCount();
            } catch (NullPointerException unused) {
                return bitmap.getRowBytes() * bitmap.getHeight();
            }
        }
        throw new IllegalStateException("Cannot obtain size for recycled Bitmap: " + bitmap + "[" + bitmap.getWidth() + "x" + bitmap.getHeight() + "] " + bitmap.getConfig());
    }

    @NonNull
    /* renamed from: e */
    public static <T> List<T> m1148e(@NonNull Collection<T> collection) {
        ArrayList arrayList = new ArrayList(collection.size());
        for (T t : collection) {
            if (t != null) {
                arrayList.add(t);
            }
        }
        return arrayList;
    }

    /* renamed from: f */
    public static int m1149f(@Nullable Object obj, int i2) {
        return (i2 * 31) + (obj == null ? 0 : obj.hashCode());
    }

    /* renamed from: g */
    public static boolean m1150g() {
        return !m1151h();
    }

    /* renamed from: h */
    public static boolean m1151h() {
        return Looper.myLooper() == Looper.getMainLooper();
    }

    /* renamed from: i */
    public static boolean m1152i(int i2, int i3) {
        if (i2 > 0 || i2 == Integer.MIN_VALUE) {
            if (i3 > 0 || i3 == Integer.MIN_VALUE) {
                return true;
            }
        }
        return false;
    }
}
