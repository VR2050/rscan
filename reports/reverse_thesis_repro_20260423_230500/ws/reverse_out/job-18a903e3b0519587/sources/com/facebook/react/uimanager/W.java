package com.facebook.react.uimanager;

import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.ReadableType;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class W {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f7531c = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f7532a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final X f7533b;

    public static final class a {

        /* JADX INFO: renamed from: com.facebook.react.uimanager.W$a$a, reason: collision with other inner class name */
        public /* synthetic */ class C0113a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            public static final /* synthetic */ int[] f7534a;

            static {
                int[] iArr = new int[ReadableType.values().length];
                try {
                    iArr[ReadableType.Number.ordinal()] = 1;
                } catch (NoSuchFieldError unused) {
                }
                try {
                    iArr[ReadableType.String.ordinal()] = 2;
                } catch (NoSuchFieldError unused2) {
                }
                f7534a = iArr;
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final W a(Dynamic dynamic) {
            t2.j.f(dynamic, "dynamic");
            int i3 = C0113a.f7534a[dynamic.getType().ordinal()];
            if (i3 == 1) {
                double dAsDouble = dynamic.asDouble();
                if (dAsDouble >= 0.0d) {
                    return new W((float) dAsDouble, X.f7535b);
                }
                return null;
            }
            if (i3 != 2) {
                Y.a.I("ReactNative", "Unsupported type for radius property: " + dynamic.getType());
                return null;
            }
            String strAsString = dynamic.asString();
            if (!z2.g.i(strAsString, "%", false, 2, null)) {
                Y.a.I("ReactNative", "Invalid string value: " + strAsString);
                return null;
            }
            try {
                String strSubstring = strAsString.substring(0, strAsString.length() - 1);
                t2.j.e(strSubstring, "substring(...)");
                float f3 = Float.parseFloat(strSubstring);
                if (f3 >= 0.0f) {
                    return new W(f3, X.f7536c);
                }
                return null;
            } catch (NumberFormatException unused) {
                Y.a.I("ReactNative", "Invalid percentage format: " + strAsString);
                return null;
            }
        }

        private a() {
        }
    }

    public W(float f3, X x3) {
        t2.j.f(x3, "type");
        this.f7532a = f3;
        this.f7533b = x3;
    }

    public final X a() {
        return this.f7533b;
    }

    public final float b(float f3) {
        return this.f7533b == X.f7536c ? (this.f7532a / 100) * f3 : this.f7532a;
    }

    public final Q1.k c(float f3, float f4) {
        if (this.f7533b != X.f7536c) {
            float f5 = this.f7532a;
            return new Q1.k(f5, f5);
        }
        float f6 = this.f7532a;
        float f7 = 100;
        return new Q1.k((f6 / f7) * f3, (f6 / f7) * f4);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof W)) {
            return false;
        }
        W w3 = (W) obj;
        return Float.compare(this.f7532a, w3.f7532a) == 0 && this.f7533b == w3.f7533b;
    }

    public int hashCode() {
        return (Float.hashCode(this.f7532a) * 31) + this.f7533b.hashCode();
    }

    public String toString() {
        return "LengthPercentage(value=" + this.f7532a + ", type=" + this.f7533b + ")";
    }
}
