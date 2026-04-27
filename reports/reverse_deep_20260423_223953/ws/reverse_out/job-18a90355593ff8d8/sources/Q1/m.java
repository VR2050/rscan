package Q1;

import android.content.Context;
import android.graphics.LinearGradient;
import android.graphics.Shader;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import h2.C0562h;
import h2.C0563i;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.List;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX INFO: loaded from: classes.dex */
public final class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ReadableArray f2463a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Context f2464b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final a f2465c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ArrayList f2466d;

    private static abstract class a {

        /* JADX INFO: renamed from: Q1.m$a$a, reason: collision with other inner class name */
        public static final class C0037a extends a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            private final double f2467a;

            public C0037a(double d3) {
                super(null);
                this.f2467a = d3;
            }

            public final double a() {
                return this.f2467a;
            }

            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                return (obj instanceof C0037a) && Double.compare(this.f2467a, ((C0037a) obj).f2467a) == 0;
            }

            public int hashCode() {
                return Double.hashCode(this.f2467a);
            }

            public String toString() {
                return "Angle(value=" + this.f2467a + ")";
            }
        }

        public static final class b extends a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            private final c f2468a;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public b(c cVar) {
                super(null);
                t2.j.f(cVar, "value");
                this.f2468a = cVar;
            }

            public final c a() {
                return this.f2468a;
            }

            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                return (obj instanceof b) && this.f2468a == ((b) obj).f2468a;
            }

            public int hashCode() {
                return this.f2468a.hashCode();
            }

            public String toString() {
                return "Keyword(value=" + this.f2468a + ")";
            }
        }

        /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
        /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
        public static final class c {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            public static final c f2469b = new c("TO_TOP_RIGHT", 0);

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            public static final c f2470c = new c("TO_BOTTOM_RIGHT", 1);

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            public static final c f2471d = new c("TO_TOP_LEFT", 2);

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            public static final c f2472e = new c("TO_BOTTOM_LEFT", 3);

            /* JADX INFO: renamed from: f, reason: collision with root package name */
            private static final /* synthetic */ c[] f2473f;

            /* JADX INFO: renamed from: g, reason: collision with root package name */
            private static final /* synthetic */ EnumEntries f2474g;

            static {
                c[] cVarArrA = a();
                f2473f = cVarArrA;
                f2474g = AbstractC0628a.a(cVarArrA);
            }

            private c(String str, int i3) {
            }

            private static final /* synthetic */ c[] a() {
                return new c[]{f2469b, f2470c, f2471d, f2472e};
            }

            public static c valueOf(String str) {
                return (c) Enum.valueOf(c.class, str);
            }

            public static c[] values() {
                return (c[]) f2473f.clone();
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f2475a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final /* synthetic */ int[] f2476b;

        static {
            int[] iArr = new int[a.c.values().length];
            try {
                iArr[a.c.f2469b.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[a.c.f2470c.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[a.c.f2471d.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[a.c.f2472e.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            f2475a = iArr;
            int[] iArr2 = new int[X.values().length];
            try {
                iArr2[X.f7535b.ordinal()] = 1;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                iArr2[X.f7536c.ordinal()] = 2;
            } catch (NoSuchFieldError unused6) {
            }
            f2476b = iArr2;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public m(ReadableMap readableMap, ReadableArray readableArray, Context context) {
        a.c cVar;
        a bVar;
        t2.j.f(readableMap, "directionMap");
        t2.j.f(readableArray, "colorStopsArray");
        t2.j.f(context, "context");
        this.f2463a = readableArray;
        this.f2464b = context;
        String string = readableMap.getString("type");
        if (!t2.j.b(string, "angle")) {
            if (!t2.j.b(string, "keyword")) {
                throw new IllegalArgumentException("Invalid direction type: " + string);
            }
            String string2 = readableMap.getString("value");
            if (string2 != null) {
                switch (string2.hashCode()) {
                    case -1849920841:
                        if (string2.equals("to bottom left")) {
                            cVar = a.c.f2472e;
                            bVar = new a.b(cVar);
                        }
                        break;
                    case -1507310228:
                        if (string2.equals("to bottom right")) {
                            cVar = a.c.f2470c;
                            bVar = new a.b(cVar);
                        }
                        break;
                    case -1359525897:
                        if (string2.equals("to top left")) {
                            cVar = a.c.f2471d;
                            bVar = new a.b(cVar);
                        }
                        break;
                    case 810031148:
                        if (string2.equals("to top right")) {
                            cVar = a.c.f2469b;
                            bVar = new a.b(cVar);
                        }
                        break;
                }
            }
            throw new IllegalArgumentException("Invalid linear gradient direction keyword: " + readableMap.getString("value"));
        }
        bVar = new a.C0037a(readableMap.getDouble("value"));
        this.f2465c = bVar;
        ArrayList arrayList = new ArrayList(readableArray.size());
        int size = readableArray.size();
        for (int i3 = 0; i3 < size; i3++) {
            ReadableMap map = this.f2463a.getMap(i3);
            if (map != null) {
                arrayList.add(new i((!map.hasKey("color") || map.isNull("color")) ? null : map.getType("color") == ReadableType.Map ? ColorPropConverter.getColor(map.getMap("color"), this.f2464b) : Integer.valueOf(map.getInt("color")), W.f7531c.a(map.getDynamic("position"))));
            }
        }
        this.f2466d = arrayList;
    }

    private final C0563i a(double d3, float f3, float f4) {
        double d4 = 360;
        double d5 = d3 % d4;
        if (d5 < 0.0d) {
            d5 += d4;
        }
        if (d5 == 0.0d) {
            return new C0563i(new float[]{0.0f, f3}, new float[]{0.0f, 0.0f});
        }
        if (d5 == 90.0d) {
            return new C0563i(new float[]{0.0f, 0.0f}, new float[]{f4, 0.0f});
        }
        if (d5 == 180.0d) {
            return new C0563i(new float[]{0.0f, 0.0f}, new float[]{0.0f, f3});
        }
        if (d5 == 270.0d) {
            return new C0563i(new float[]{f4, 0.0f}, new float[]{0.0f, 0.0f});
        }
        float fTan = (float) Math.tan(Math.toRadians(((double) 90) - d5));
        float f5 = (-1) / fTan;
        float f6 = 2;
        float f7 = f3 / f6;
        float f8 = f4 / f6;
        float[] fArr = d5 < 90.0d ? new float[]{f8, f7} : d5 < 180.0d ? new float[]{f8, -f7} : d5 < 270.0d ? new float[]{-f8, -f7} : new float[]{-f8, f7};
        float f9 = fArr[1] - (fArr[0] * f5);
        float f10 = f9 / (fTan - f5);
        float f11 = (f5 * f10) + f9;
        return new C0563i(new float[]{f8 - f10, f7 + f11}, new float[]{f8 + f10, f7 - f11});
    }

    private final double b(a.c cVar, double d3, double d4) {
        double degrees;
        double d5;
        int i3;
        int i4 = b.f2475a[cVar.ordinal()];
        if (i4 == 1) {
            return ((double) 90) - Math.toDegrees(Math.atan(d3 / d4));
        }
        if (i4 != 2) {
            if (i4 == 3) {
                degrees = Math.toDegrees(Math.atan(d3 / d4));
                i3 = 270;
            } else {
                if (i4 != 4) {
                    throw new C0562h();
                }
                degrees = Math.toDegrees(Math.atan(d4 / d3));
                i3 = 180;
            }
            d5 = i3;
        } else {
            degrees = Math.toDegrees(Math.atan(d3 / d4));
            d5 = 90;
        }
        return degrees + d5;
    }

    private final q[] c(ArrayList arrayList, float f3) {
        Float fB;
        int size = arrayList.size();
        q[] qVarArr = new q[size];
        int i3 = 0;
        for (int i4 = 0; i4 < size; i4++) {
            qVarArr[i4] = new q(null, null, 3, null);
        }
        Float f4 = f(((i) arrayList.get(0)).b(), f3);
        float fFloatValue = f4 != null ? f4.floatValue() : 0.0f;
        int size2 = arrayList.size();
        int i5 = 0;
        boolean z3 = false;
        while (i5 < size2) {
            Object obj = arrayList.get(i5);
            t2.j.e(obj, "get(...)");
            i iVar = (i) obj;
            Float f5 = f(iVar.b(), f3);
            if (f5 == null) {
                f5 = i5 == 0 ? Float.valueOf(0.0f) : i5 == arrayList.size() - 1 ? Float.valueOf(1.0f) : null;
            }
            if (f5 != null) {
                fFloatValue = Math.max(f5.floatValue(), fFloatValue);
                qVarArr[i5] = new q(iVar.a(), Float.valueOf(fFloatValue));
            } else {
                z3 = true;
            }
            i5++;
        }
        if (z3) {
            for (int i6 = 1; i6 < size; i6++) {
                Float fB2 = qVarArr[i6].b();
                if (fB2 != null) {
                    int i7 = i6 - i3;
                    int i8 = i7 - 1;
                    if (i8 > 0 && (fB = qVarArr[i3].b()) != null) {
                        float fFloatValue2 = (fB2.floatValue() - fB.floatValue()) / i7;
                        if (1 <= i8) {
                            int i9 = 1;
                            while (true) {
                                int i10 = i3 + i9;
                                qVarArr[i10] = new q(((i) arrayList.get(i10)).a(), Float.valueOf(fB.floatValue() + (i9 * fFloatValue2)));
                                if (i9 == i8) {
                                    break;
                                }
                                i9++;
                            }
                        }
                    }
                    i3 = i6;
                }
            }
        }
        return qVarArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x007e A[PHI: r6
      0x007e: PHI (r6v2 int) = (r6v1 int), (r6v1 int), (r6v1 int), (r6v1 int), (r6v1 int), (r6v1 int), (r6v1 int), (r6v5 int) binds: [B:5:0x0013, B:8:0x0018, B:11:0x003d, B:12:0x003f, B:13:0x0041, B:24:0x0099, B:21:0x0089, B:17:0x0079] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.util.List e(Q1.q[] r23) {
        /*
            Method dump skipped, instruction units count: 468
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: Q1.m.e(Q1.q[]):java.util.List");
    }

    private final Float f(W w3, float f3) {
        if (w3 == null) {
            return null;
        }
        int i3 = b.f2476b[w3.a().ordinal()];
        if (i3 == 1) {
            return Float.valueOf(C0444f0.h(w3.b(0.0f)) / f3);
        }
        if (i3 == 2) {
            return Float.valueOf(w3.b(1.0f));
        }
        throw new C0562h();
    }

    public final Shader d(float f3, float f4) {
        double dB;
        a aVar = this.f2465c;
        if (aVar instanceof a.C0037a) {
            dB = ((a.C0037a) aVar).a();
        } else {
            if (!(aVar instanceof a.b)) {
                throw new C0562h();
            }
            dB = b(((a.b) aVar).a(), f3, f4);
        }
        C0563i c0563iA = a(dB, f4, f3);
        float[] fArr = (float[]) c0563iA.a();
        float[] fArr2 = (float[]) c0563iA.b();
        float f5 = fArr2[0] - fArr[0];
        float f6 = fArr2[1] - fArr[1];
        List listE = e(c(this.f2466d, (float) Math.sqrt((f5 * f5) + (f6 * f6))));
        int[] iArr = new int[listE.size()];
        float[] fArr3 = new float[listE.size()];
        int i3 = 0;
        for (Object obj : listE) {
            int i4 = i3 + 1;
            if (i3 < 0) {
                AbstractC0586n.n();
            }
            q qVar = (q) obj;
            Integer numA = qVar.a();
            if (numA != null && qVar.b() != null) {
                iArr[i3] = numA.intValue();
                fArr3[i3] = qVar.b().floatValue();
            }
            i3 = i4;
        }
        return new LinearGradient(fArr[0], fArr[1], fArr2[0], fArr2[1], iArr, fArr3, Shader.TileMode.CLAMP);
    }
}
