package O1;

import android.view.View;
import c1.AbstractC0339k;
import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX INFO: loaded from: classes.dex */
public final class o {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final o f2104a = new o();

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    public static final class a {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final a f2105b = new a("CANCEL", 0);

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final a f2106c = new a("CANCEL_CAPTURE", 1);

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public static final a f2107d = new a("CLICK", 2);

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public static final a f2108e = new a("CLICK_CAPTURE", 3);

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public static final a f2109f = new a("DOWN", 4);

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        public static final a f2110g = new a("DOWN_CAPTURE", 5);

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        public static final a f2111h = new a("ENTER", 6);

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        public static final a f2112i = new a("ENTER_CAPTURE", 7);

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        public static final a f2113j = new a("LEAVE", 8);

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        public static final a f2114k = new a("LEAVE_CAPTURE", 9);

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        public static final a f2115l = new a("MOVE", 10);

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        public static final a f2116m = new a("MOVE_CAPTURE", 11);

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        public static final a f2117n = new a("UP", 12);

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        public static final a f2118o = new a("UP_CAPTURE", 13);

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        public static final a f2119p = new a("OUT", 14);

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        public static final a f2120q = new a("OUT_CAPTURE", 15);

        /* JADX INFO: renamed from: r, reason: collision with root package name */
        public static final a f2121r = new a("OVER", 16);

        /* JADX INFO: renamed from: s, reason: collision with root package name */
        public static final a f2122s = new a("OVER_CAPTURE", 17);

        /* JADX INFO: renamed from: t, reason: collision with root package name */
        private static final /* synthetic */ a[] f2123t;

        /* JADX INFO: renamed from: u, reason: collision with root package name */
        private static final /* synthetic */ EnumEntries f2124u;

        static {
            a[] aVarArrA = a();
            f2123t = aVarArrA;
            f2124u = AbstractC0628a.a(aVarArrA);
        }

        private a(String str, int i3) {
        }

        private static final /* synthetic */ a[] a() {
            return new a[]{f2105b, f2106c, f2107d, f2108e, f2109f, f2110g, f2111h, f2112i, f2113j, f2114k, f2115l, f2116m, f2117n, f2118o, f2119p, f2120q, f2121r, f2122s};
        }

        public static a valueOf(String str) {
            return (a) Enum.valueOf(a.class, str);
        }

        public static a[] values() {
            return (a[]) f2123t.clone();
        }
    }

    public /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f2125a;

        static {
            int[] iArr = new int[a.values().length];
            try {
                iArr[a.f2109f.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[a.f2110g.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[a.f2117n.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[a.f2118o.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                iArr[a.f2105b.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                iArr[a.f2106c.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                iArr[a.f2107d.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                iArr[a.f2108e.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            f2125a = iArr;
        }
    }

    private o() {
    }

    public static final int a(String str, int i3, int i4) {
        t2.j.f(str, "pointerType");
        if (t2.j.b("touch", str)) {
            return 0;
        }
        int i5 = i4 ^ i3;
        if (i5 == 0) {
            return -1;
        }
        if (i5 == 1) {
            return 0;
        }
        if (i5 == 2) {
            return 2;
        }
        if (i5 == 4) {
            return 1;
        }
        if (i5 != 8) {
            return i5 != 16 ? -1 : 4;
        }
        return 3;
    }

    public static final int b(String str, String str2, int i3) {
        t2.j.f(str2, "pointerType");
        if (f2104a.g(str)) {
            return 0;
        }
        if (t2.j.b("touch", str2)) {
            return 1;
        }
        return i3;
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static final int c(String str) {
        if (str == null) {
            return 2;
        }
        switch (str.hashCode()) {
            case -1786514288:
                if (!str.equals("topPointerEnter")) {
                }
                break;
            case -1780335505:
                if (!str.equals("topPointerLeave")) {
                }
                break;
            case -1304584214:
                if (!str.equals("topPointerDown")) {
                }
                break;
            case -1304316135:
                if (!str.equals("topPointerMove")) {
                }
                break;
            case -1304250340:
                if (!str.equals("topPointerOver")) {
                }
                break;
            case -1065042973:
                if (!str.equals("topPointerUp")) {
                }
                break;
            case 383186882:
                if (!str.equals("topPointerCancel")) {
                }
                break;
            case 1343400710:
                if (!str.equals("topPointerOut")) {
                }
                break;
        }
        return 2;
    }

    public static final double d(int i3, String str) {
        return (f2104a.g(str) || i3 == 0) ? 0.0d : 0.5d;
    }

    public static final String e(int i3) {
        return i3 != 1 ? i3 != 2 ? i3 != 3 ? "" : "mouse" : "pen" : "touch";
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0040 A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean f(java.lang.String r1) {
        /*
            if (r1 == 0) goto L42
            int r0 = r1.hashCode()
            switch(r0) {
                case -1304584214: goto L37;
                case -1304316135: goto L2e;
                case -1304250340: goto L25;
                case -1065042973: goto L1c;
                case 383186882: goto L13;
                case 1343400710: goto La;
                default: goto L9;
            }
        L9:
            goto L42
        La:
            java.lang.String r0 = "topPointerOut"
            boolean r1 = r1.equals(r0)
            if (r1 != 0) goto L40
            goto L42
        L13:
            java.lang.String r0 = "topPointerCancel"
            boolean r1 = r1.equals(r0)
            if (r1 != 0) goto L40
            goto L42
        L1c:
            java.lang.String r0 = "topPointerUp"
            boolean r1 = r1.equals(r0)
            if (r1 != 0) goto L40
            goto L42
        L25:
            java.lang.String r0 = "topPointerOver"
            boolean r1 = r1.equals(r0)
            if (r1 == 0) goto L42
            goto L40
        L2e:
            java.lang.String r0 = "topPointerMove"
            boolean r1 = r1.equals(r0)
            if (r1 != 0) goto L40
            goto L42
        L37:
            java.lang.String r0 = "topPointerDown"
            boolean r1 = r1.equals(r0)
            if (r1 != 0) goto L40
            goto L42
        L40:
            r1 = 1
            goto L43
        L42:
            r1 = 0
        L43:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: O1.o.f(java.lang.String):boolean");
    }

    public static final boolean h(View view, a aVar) {
        t2.j.f(aVar, "event");
        if (view == null) {
            return true;
        }
        switch (b.f2125a[aVar.ordinal()]) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
                break;
            default:
                Object tag = view.getTag(AbstractC0339k.f5595s);
                Integer num = tag instanceof Integer ? (Integer) tag : null;
                if (num == null || (num.intValue() & (1 << aVar.ordinal())) == 0) {
                }
                break;
        }
        return true;
    }

    public final boolean g(String str) {
        int iHashCode;
        return str != null && ((iHashCode = str.hashCode()) == -1780335505 ? str.equals("topPointerLeave") : !(iHashCode == -1065042973 ? !str.equals("topPointerUp") : !(iHashCode == 1343400710 && str.equals("topPointerOut"))));
    }
}
