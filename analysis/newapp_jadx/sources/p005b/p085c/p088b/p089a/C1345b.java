package p005b.p085c.p088b.p089a;

import java.util.Objects;

/* renamed from: b.c.b.a.b */
/* loaded from: classes.dex */
public /* synthetic */ class C1345b {

    /* renamed from: a */
    public static /* synthetic */ int[] f1146a;

    /* renamed from: b */
    public static /* synthetic */ int[] f1147b;

    /* renamed from: c */
    public static /* synthetic */ int[] f1148c;

    /* renamed from: d */
    public static /* synthetic */ int[] f1149d;

    /* renamed from: e */
    public static /* synthetic */ int[] f1150e;

    /* renamed from: f */
    public static /* synthetic */ int[] f1151f;

    /* renamed from: g */
    public static /* synthetic */ int[] f1152g;

    /* renamed from: h */
    public static /* synthetic */ int[] f1153h;

    /* renamed from: i */
    public static /* synthetic */ int[] f1154i;

    /* renamed from: j */
    public static /* synthetic */ int[] f1155j;

    /* renamed from: k */
    public static /* synthetic */ int[] f1156k;

    /* renamed from: l */
    public static /* synthetic */ int[] f1157l;

    /* renamed from: m */
    public static /* synthetic */ int[] f1158m;

    /* renamed from: n */
    public static /* synthetic */ int[] f1159n;

    /* renamed from: o */
    public static /* synthetic */ int[] f1160o;

    /* renamed from: p */
    public static /* synthetic */ int[] f1161p;

    /* renamed from: q */
    public static /* synthetic */ int[] f1162q;

    /* renamed from: a */
    public static synchronized /* synthetic */ int[] m349a() {
        int[] iArr;
        synchronized (C1345b.class) {
            if (f1158m == null) {
                f1158m = m351c(2);
            }
            iArr = f1158m;
        }
        return iArr;
    }

    /* renamed from: b */
    public static /* synthetic */ int m350b(int i2) {
        if (i2 != 0) {
            return i2 - 1;
        }
        throw null;
    }

    /* renamed from: c */
    public static /* synthetic */ int[] m351c(int i2) {
        int[] iArr = new int[i2];
        int i3 = 0;
        while (i3 < i2) {
            int i4 = i3 + 1;
            iArr[i3] = i4;
            i3 = i4;
        }
        return iArr;
    }

    public static int[] com$king$zxing$ViewfinderView$TextLocation$s$values() {
        return (int[]) m349a().clone();
    }

    /* renamed from: d */
    public static /* synthetic */ void m352d(int i2) {
        if (i2 == 0) {
            throw null;
        }
    }

    /* renamed from: e */
    public static /* synthetic */ int m353e(String str) {
        Objects.requireNonNull(str, "Name is null");
        if (str.equals("ON")) {
            return 1;
        }
        if (str.equals("AUTO")) {
            return 2;
        }
        if (str.equals("OFF")) {
            return 3;
        }
        throw new IllegalArgumentException("No enum constant com.king.zxing.camera.FrontLightMode.".concat(str));
    }
}
