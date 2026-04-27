package Q1;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.Shader;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import h2.C0562h;
import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX INFO: loaded from: classes.dex */
public final class l {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final a f2457a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final m f2458b;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    private static final class a {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final a f2459b = new a("LINEAR_GRADIENT", 0);

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private static final /* synthetic */ a[] f2460c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private static final /* synthetic */ EnumEntries f2461d;

        static {
            a[] aVarArrA = a();
            f2460c = aVarArrA;
            f2461d = AbstractC0628a.a(aVarArrA);
        }

        private a(String str, int i3) {
        }

        private static final /* synthetic */ a[] a() {
            return new a[]{f2459b};
        }

        public static a valueOf(String str) {
            return (a) Enum.valueOf(a.class, str);
        }

        public static a[] values() {
            return (a[]) f2460c.clone();
        }
    }

    public /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f2462a;

        static {
            int[] iArr = new int[a.values().length];
            try {
                iArr[a.f2459b.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            f2462a = iArr;
        }
    }

    public l(ReadableMap readableMap, Context context) {
        t2.j.f(context, "context");
        if (readableMap == null) {
            throw new IllegalArgumentException("Gradient cannot be null");
        }
        String string = readableMap.getString("type");
        if (!t2.j.b(string, "linearGradient")) {
            throw new IllegalArgumentException("Unsupported gradient type: " + string);
        }
        this.f2457a = a.f2459b;
        ReadableMap map = readableMap.getMap("direction");
        if (map == null) {
            throw new IllegalArgumentException("Gradient must have direction");
        }
        ReadableArray array = readableMap.getArray("colorStops");
        if (array == null) {
            throw new IllegalArgumentException("Invalid colorStops array");
        }
        this.f2458b = new m(map, array, context);
    }

    public final Shader a(Rect rect) {
        t2.j.f(rect, "bounds");
        if (b.f2462a[this.f2457a.ordinal()] == 1) {
            return this.f2458b.d(rect.width(), rect.height());
        }
        throw new C0562h();
    }
}
