package T0;

import H0.f;
import H0.g;
import H0.h;
import I0.EnumC0189n;
import X.e;
import X.i;
import X.k;
import a1.C0224a;
import android.net.Uri;
import android.os.Build;
import java.io.File;

/* JADX INFO: loaded from: classes.dex */
public class b {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    public static final e f2742A = new a();

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private static boolean f2743y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private static boolean f2744z;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f2745a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final EnumC0041b f2746b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Uri f2747c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f2748d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private File f2749e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f2750f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f2751g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final boolean f2752h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final H0.d f2753i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final g f2754j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final h f2755k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final H0.b f2756l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final f f2757m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final c f2758n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    protected int f2759o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final boolean f2760p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final boolean f2761q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final Boolean f2762r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final d f2763s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final P0.e f2764t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final Boolean f2765u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final EnumC0189n f2766v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private final String f2767w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private final int f2768x;

    class a implements e {
        a() {
        }

        @Override // X.e
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public Uri a(b bVar) {
            if (bVar != null) {
                return bVar.v();
            }
            return null;
        }
    }

    /* JADX INFO: renamed from: T0.b$b, reason: collision with other inner class name */
    public enum EnumC0041b {
        SMALL,
        DEFAULT,
        DYNAMIC
    }

    public enum c {
        FULL_FETCH(1),
        DISK_CACHE(2),
        ENCODED_MEMORY_CACHE(3),
        BITMAP_MEMORY_CACHE(4);


        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f2778b;

        c(int i3) {
            this.f2778b = i3;
        }

        public static c a(c cVar, c cVar2) {
            return cVar.b() > cVar2.b() ? cVar : cVar2;
        }

        public int b() {
            return this.f2778b;
        }
    }

    protected b(T0.c cVar) {
        this.f2746b = cVar.d();
        Uri uriR = cVar.r();
        this.f2747c = uriR;
        this.f2748d = x(uriR);
        this.f2750f = cVar.w();
        this.f2751g = cVar.u();
        this.f2752h = cVar.j();
        this.f2753i = cVar.i();
        this.f2754j = cVar.o();
        this.f2755k = cVar.q() == null ? h.c() : cVar.q();
        this.f2756l = cVar.c();
        this.f2757m = cVar.n();
        this.f2758n = cVar.k();
        boolean zT = cVar.t();
        this.f2760p = zT;
        int iE = cVar.e();
        this.f2759o = zT ? iE : iE | 48;
        this.f2761q = cVar.v();
        this.f2762r = cVar.S();
        this.f2763s = cVar.l();
        this.f2764t = cVar.m();
        this.f2765u = cVar.p();
        this.f2766v = cVar.h();
        this.f2768x = cVar.f();
        this.f2767w = cVar.g();
    }

    public static b a(Uri uri) {
        if (uri == null) {
            return null;
        }
        return T0.c.x(uri).a();
    }

    private static int x(Uri uri) {
        if (uri == null) {
            return -1;
        }
        if (f0.f.n(uri)) {
            return 0;
        }
        if (uri.getPath() != null && f0.f.l(uri)) {
            return Z.a.c(Z.a.b(uri.getPath())) ? 2 : 3;
        }
        if (f0.f.k(uri)) {
            return 4;
        }
        if (f0.f.h(uri)) {
            return 5;
        }
        if (f0.f.m(uri)) {
            return 6;
        }
        if (f0.f.g(uri)) {
            return 7;
        }
        return f0.f.o(uri) ? 8 : -1;
    }

    public H0.b b() {
        return this.f2756l;
    }

    public EnumC0041b c() {
        return this.f2746b;
    }

    public int d() {
        return this.f2759o;
    }

    public int e() {
        return this.f2768x;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        if (f2743y) {
            int i3 = this.f2745a;
            int i4 = bVar.f2745a;
            if (i3 != 0 && i4 != 0 && i3 != i4) {
                return false;
            }
        }
        if (this.f2751g != bVar.f2751g || this.f2760p != bVar.f2760p || this.f2761q != bVar.f2761q || !i.a(this.f2747c, bVar.f2747c) || !i.a(this.f2746b, bVar.f2746b) || !i.a(this.f2767w, bVar.f2767w) || !i.a(this.f2749e, bVar.f2749e) || !i.a(this.f2756l, bVar.f2756l) || !i.a(this.f2753i, bVar.f2753i) || !i.a(this.f2754j, bVar.f2754j) || !i.a(this.f2757m, bVar.f2757m) || !i.a(this.f2758n, bVar.f2758n) || !i.a(Integer.valueOf(this.f2759o), Integer.valueOf(bVar.f2759o)) || !i.a(this.f2762r, bVar.f2762r) || !i.a(this.f2765u, bVar.f2765u) || !i.a(this.f2766v, bVar.f2766v) || !i.a(this.f2755k, bVar.f2755k) || this.f2752h != bVar.f2752h) {
            return false;
        }
        d dVar = this.f2763s;
        R.d dVarB = dVar != null ? dVar.b() : null;
        d dVar2 = bVar.f2763s;
        return i.a(dVarB, dVar2 != null ? dVar2.b() : null) && this.f2768x == bVar.f2768x;
    }

    public String f() {
        return this.f2767w;
    }

    public EnumC0189n g() {
        return this.f2766v;
    }

    public H0.d h() {
        return this.f2753i;
    }

    public int hashCode() {
        boolean z3 = f2744z;
        int iA = z3 ? this.f2745a : 0;
        if (iA == 0) {
            d dVar = this.f2763s;
            iA = C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(C0224a.a(0, this.f2746b), this.f2747c), Boolean.valueOf(this.f2751g)), this.f2756l), this.f2757m), this.f2758n), Integer.valueOf(this.f2759o)), Boolean.valueOf(this.f2760p)), Boolean.valueOf(this.f2761q)), this.f2753i), this.f2762r), this.f2754j), this.f2755k), dVar != null ? dVar.b() : null), this.f2765u), this.f2766v), Integer.valueOf(this.f2768x)), Boolean.valueOf(this.f2752h));
            if (z3) {
                this.f2745a = iA;
            }
        }
        return iA;
    }

    public boolean i() {
        return Build.VERSION.SDK_INT >= 29 && this.f2752h;
    }

    public boolean j() {
        return this.f2751g;
    }

    public c k() {
        return this.f2758n;
    }

    public d l() {
        return this.f2763s;
    }

    public int m() {
        g gVar = this.f2754j;
        if (gVar != null) {
            return gVar.f1022b;
        }
        return 2048;
    }

    public int n() {
        g gVar = this.f2754j;
        if (gVar != null) {
            return gVar.f1021a;
        }
        return 2048;
    }

    public f o() {
        return this.f2757m;
    }

    public boolean p() {
        return this.f2750f;
    }

    public P0.e q() {
        return this.f2764t;
    }

    public g r() {
        return this.f2754j;
    }

    public Boolean s() {
        return this.f2765u;
    }

    public h t() {
        return this.f2755k;
    }

    public String toString() {
        return i.b(this).b("uri", this.f2747c).b("cacheChoice", this.f2746b).b("decodeOptions", this.f2753i).b("postprocessor", this.f2763s).b("priority", this.f2757m).b("resizeOptions", this.f2754j).b("rotationOptions", this.f2755k).b("bytesRange", this.f2756l).b("resizingAllowedOverride", this.f2765u).b("downsampleOverride", this.f2766v).c("progressiveRenderingEnabled", this.f2750f).c("localThumbnailPreviewsEnabled", this.f2751g).c("loadThumbnailOnly", this.f2752h).b("lowestPermittedRequestLevel", this.f2758n).a("cachesDisabled", this.f2759o).c("isDiskCacheEnabled", this.f2760p).c("isMemoryCacheEnabled", this.f2761q).b("decodePrefetches", this.f2762r).a("delayMs", this.f2768x).toString();
    }

    public synchronized File u() {
        try {
            if (this.f2749e == null) {
                k.g(this.f2747c.getPath());
                this.f2749e = new File(this.f2747c.getPath());
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.f2749e;
    }

    public Uri v() {
        return this.f2747c;
    }

    public int w() {
        return this.f2748d;
    }

    public boolean y(int i3) {
        return (i3 & d()) == 0;
    }

    public Boolean z() {
        return this.f2762r;
    }
}
