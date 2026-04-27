package C0;

import C0.c;
import g0.AbstractC0532b;
import i2.AbstractC0580h;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a implements c.b {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final byte[] f529c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final int f530d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final byte[] f531e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final int f532f;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final byte[] f535i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final int f536j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static final byte[] f537k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static final int f538l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static final byte[] f539m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static final byte[][] f540n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final byte[] f541o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final byte[] f542p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private static final int f543q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private static final byte[] f544r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private static final byte[] f545s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private static final byte[] f546t;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f547a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final C0011a f528b = new C0011a(null);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final byte[] f533g = f.a("GIF87a");

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final byte[] f534h = f.a("GIF89a");

    /* JADX INFO: renamed from: C0.a$a, reason: collision with other inner class name */
    public static final class C0011a {
        public /* synthetic */ C0011a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private final int k(byte[] bArr) {
            if (bArr.length < 4) {
                return -1;
            }
            return (bArr[3] & 255) | ((bArr[0] & 255) << 24) | ((bArr[1] & 255) << 16) | ((bArr[2] & 255) << 8);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final c l(byte[] bArr, int i3) {
            if (AbstractC0532b.h(bArr, 0, i3)) {
                return AbstractC0532b.g(bArr, 0) ? b.f554g : AbstractC0532b.f(bArr, 0) ? b.f555h : AbstractC0532b.c(bArr, 0, i3) ? AbstractC0532b.b(bArr, 0) ? b.f558k : AbstractC0532b.d(bArr, 0) ? b.f557j : b.f556i : c.f565d;
            }
            throw new IllegalStateException("Check failed.");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean m(byte[] bArr, int i3) {
            if (i3 >= 12 && k(bArr) >= 8 && f.b(bArr, a.f545s, 4)) {
                return f.b(bArr, a.f546t, 8);
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean n(byte[] bArr, int i3) {
            return i3 >= 4 && f.c(bArr, a.f544r);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean o(byte[] bArr, int i3) {
            if (i3 < a.f535i.length) {
                return false;
            }
            return f.c(bArr, a.f535i);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean p(byte[] bArr, int i3) {
            return i3 >= a.f543q && (f.c(bArr, a.f541o) || f.c(bArr, a.f542p));
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean q(byte[] bArr, int i3) {
            if (i3 < 6) {
                return false;
            }
            return f.c(bArr, a.f533g) || f.c(bArr, a.f534h);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean r(byte[] bArr, int i3) {
            if (i3 < 12 || bArr[3] < 8 || !f.b(bArr, a.f539m, 4)) {
                return false;
            }
            for (byte[] bArr2 : a.f540n) {
                if (f.b(bArr, bArr2, 8)) {
                    return true;
                }
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean s(byte[] bArr, int i3) {
            if (i3 < a.f537k.length) {
                return false;
            }
            return f.c(bArr, a.f537k);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean t(byte[] bArr, int i3) {
            return i3 >= a.f529c.length && f.c(bArr, a.f529c);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean u(byte[] bArr, int i3) {
            return i3 >= a.f531e.length && f.c(bArr, a.f531e);
        }

        private C0011a() {
        }
    }

    static {
        byte[] bArr = {-1, -40, -1};
        f529c = bArr;
        f530d = bArr.length;
        byte[] bArr2 = {-119, 80, 78, 71, 13, 10, 26, 10};
        f531e = bArr2;
        f532f = bArr2.length;
        byte[] bArrA = f.a("BM");
        f535i = bArrA;
        f536j = bArrA.length;
        byte[] bArr3 = {0, 0, 1, 0};
        f537k = bArr3;
        f538l = bArr3.length;
        f539m = f.a("ftyp");
        f540n = new byte[][]{f.a("heic"), f.a("heix"), f.a("hevc"), f.a("hevx"), f.a("mif1"), f.a("msf1")};
        byte[] bArr4 = {73, 73, 42, 0};
        f541o = bArr4;
        f542p = new byte[]{77, 77, 0, 42};
        f543q = bArr4.length;
        f544r = new byte[]{3, 0, 8, 0};
        f545s = f.a("ftyp");
        f546t = f.a("avif");
    }

    public a() {
        Object objY = AbstractC0580h.y(new Integer[]{21, 20, Integer.valueOf(f530d), Integer.valueOf(f532f), 6, Integer.valueOf(f536j), Integer.valueOf(f538l), 12, 4, 12});
        if (objY == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.f547a = ((Number) objY).intValue();
    }

    @Override // C0.c.b
    public int a() {
        return this.f547a;
    }

    @Override // C0.c.b
    public c b(byte[] bArr, int i3) {
        j.f(bArr, "headerBytes");
        if (AbstractC0532b.h(bArr, 0, i3)) {
            return f528b.l(bArr, i3);
        }
        C0011a c0011a = f528b;
        return c0011a.t(bArr, i3) ? b.f549b : c0011a.u(bArr, i3) ? b.f550c : c0011a.q(bArr, i3) ? b.f551d : c0011a.o(bArr, i3) ? b.f552e : c0011a.s(bArr, i3) ? b.f553f : c0011a.m(bArr, i3) ? b.f562o : c0011a.r(bArr, i3) ? b.f559l : c0011a.n(bArr, i3) ? b.f561n : c0011a.p(bArr, i3) ? b.f560m : c.f565d;
    }
}
