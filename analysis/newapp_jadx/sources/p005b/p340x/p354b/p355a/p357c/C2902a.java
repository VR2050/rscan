package p005b.p340x.p354b.p355a.p357c;

/* renamed from: b.x.b.a.c.a */
/* loaded from: classes2.dex */
public class C2902a {

    /* renamed from: a */
    public static final C2902a f7913a;

    /* renamed from: b */
    public static final C2902a f7914b;

    /* renamed from: c */
    public static final C2902a f7915c;

    /* renamed from: d */
    public static final C2902a f7916d;

    /* renamed from: e */
    public static final C2902a f7917e;

    /* renamed from: f */
    public static final C2902a f7918f;

    /* renamed from: g */
    public static final C2902a f7919g;

    /* renamed from: h */
    public static final C2902a f7920h;

    /* renamed from: i */
    public static final C2902a f7921i;

    /* renamed from: j */
    public static final C2902a f7922j;

    /* renamed from: k */
    public static final C2902a f7923k;

    /* renamed from: l */
    public static final C2902a f7924l;

    /* renamed from: m */
    public static final C2902a[] f7925m;

    /* renamed from: n */
    public final int f7926n;

    /* renamed from: o */
    public final boolean f7927o;

    static {
        C2902a c2902a = new C2902a(0, false);
        f7913a = c2902a;
        C2902a c2902a2 = new C2902a(1, true);
        f7914b = c2902a2;
        C2902a c2902a3 = new C2902a(2, false);
        f7915c = c2902a3;
        C2902a c2902a4 = new C2902a(3, true);
        f7916d = c2902a4;
        C2902a c2902a5 = new C2902a(4, false);
        f7917e = c2902a5;
        C2902a c2902a6 = new C2902a(5, true);
        f7918f = c2902a6;
        C2902a c2902a7 = new C2902a(6, false);
        f7919g = c2902a7;
        C2902a c2902a8 = new C2902a(7, true);
        f7920h = c2902a8;
        C2902a c2902a9 = new C2902a(8, false);
        f7921i = c2902a9;
        C2902a c2902a10 = new C2902a(9, true);
        f7922j = c2902a10;
        C2902a c2902a11 = new C2902a(10, false);
        f7923k = c2902a11;
        C2902a c2902a12 = new C2902a(10, true);
        f7924l = c2902a12;
        f7925m = new C2902a[]{c2902a, c2902a2, c2902a3, c2902a4, c2902a5, c2902a6, c2902a7, c2902a8, c2902a9, c2902a10, c2902a11, c2902a12};
    }

    public C2902a(int i2, boolean z) {
        this.f7926n = i2;
        this.f7927o = z;
    }

    /* renamed from: a */
    public boolean m3357a(C2902a c2902a) {
        int i2 = this.f7926n;
        int i3 = c2902a.f7926n;
        return i2 < i3 || ((!this.f7927o || f7922j == this) && i2 == i3);
    }

    /* renamed from: b */
    public C2902a m3358b() {
        if (!this.f7927o) {
            return this;
        }
        C2902a c2902a = f7925m[this.f7926n - 1];
        return !c2902a.f7927o ? c2902a : f7913a;
    }
}
