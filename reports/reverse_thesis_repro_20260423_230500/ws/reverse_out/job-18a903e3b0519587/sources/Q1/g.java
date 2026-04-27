package Q1;

import android.content.Context;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.bridge.JSApplicationCausedNativeException;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class g {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final a f2437g = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f2438a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f2439b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Integer f2440c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Float f2441d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Float f2442e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Boolean f2443f;

    public static final class a {

        /* JADX INFO: renamed from: Q1.g$a$a, reason: collision with other inner class name */
        public /* synthetic */ class C0036a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            public static final /* synthetic */ int[] f2444a;

            static {
                int[] iArr = new int[ReadableType.values().length];
                try {
                    iArr[ReadableType.Number.ordinal()] = 1;
                } catch (NoSuchFieldError unused) {
                }
                try {
                    iArr[ReadableType.Map.ordinal()] = 2;
                } catch (NoSuchFieldError unused2) {
                }
                f2444a = iArr;
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final g a(ReadableMap readableMap, Context context) {
            Integer num;
            Integer numValueOf;
            t2.j.f(context, "context");
            if (readableMap == null || !readableMap.hasKey("offsetX") || !readableMap.hasKey("offsetY")) {
                return null;
            }
            float f3 = (float) readableMap.getDouble("offsetX");
            float f4 = (float) readableMap.getDouble("offsetY");
            if (readableMap.hasKey("color")) {
                ReadableType type = readableMap.getType("color");
                int i3 = C0036a.f2444a[type.ordinal()];
                if (i3 == 1) {
                    numValueOf = Integer.valueOf(readableMap.getInt("color"));
                } else {
                    if (i3 != 2) {
                        throw new JSApplicationCausedNativeException("Unsupported color type " + type);
                    }
                    numValueOf = ColorPropConverter.getColor(readableMap.getMap("color"), context);
                }
                num = numValueOf;
            } else {
                num = null;
            }
            return new g(f3, f4, num, readableMap.hasKey("blurRadius") ? Float.valueOf((float) readableMap.getDouble("blurRadius")) : null, readableMap.hasKey("spreadDistance") ? Float.valueOf((float) readableMap.getDouble("spreadDistance")) : null, readableMap.hasKey("inset") ? Boolean.valueOf(readableMap.getBoolean("inset")) : null);
        }

        private a() {
        }
    }

    public g(float f3, float f4, Integer num, Float f5, Float f6, Boolean bool) {
        this.f2438a = f3;
        this.f2439b = f4;
        this.f2440c = num;
        this.f2441d = f5;
        this.f2442e = f6;
        this.f2443f = bool;
    }

    public final Float a() {
        return this.f2441d;
    }

    public final Integer b() {
        return this.f2440c;
    }

    public final Boolean c() {
        return this.f2443f;
    }

    public final float d() {
        return this.f2438a;
    }

    public final float e() {
        return this.f2439b;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Float.compare(this.f2438a, gVar.f2438a) == 0 && Float.compare(this.f2439b, gVar.f2439b) == 0 && t2.j.b(this.f2440c, gVar.f2440c) && t2.j.b(this.f2441d, gVar.f2441d) && t2.j.b(this.f2442e, gVar.f2442e) && t2.j.b(this.f2443f, gVar.f2443f);
    }

    public final Float f() {
        return this.f2442e;
    }

    public int hashCode() {
        int iHashCode = ((Float.hashCode(this.f2438a) * 31) + Float.hashCode(this.f2439b)) * 31;
        Integer num = this.f2440c;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        Float f3 = this.f2441d;
        int iHashCode3 = (iHashCode2 + (f3 == null ? 0 : f3.hashCode())) * 31;
        Float f4 = this.f2442e;
        int iHashCode4 = (iHashCode3 + (f4 == null ? 0 : f4.hashCode())) * 31;
        Boolean bool = this.f2443f;
        return iHashCode4 + (bool != null ? bool.hashCode() : 0);
    }

    public String toString() {
        return "BoxShadow(offsetX=" + this.f2438a + ", offsetY=" + this.f2439b + ", color=" + this.f2440c + ", blurRadius=" + this.f2441d + ", spreadDistance=" + this.f2442e + ", inset=" + this.f2443f + ")";
    }
}
