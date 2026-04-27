package S;

import X.n;
import android.content.Context;
import java.io.File;

/* JADX INFO: loaded from: classes.dex */
public class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2661a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f2662b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final n f2663c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final long f2664d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final long f2665e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final long f2666f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final j f2667g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final R.a f2668h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final R.c f2669i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final U.b f2670j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final Context f2671k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final boolean f2672l;

    class a implements n {
        a() {
        }

        @Override // X.n
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public File get() {
            X.k.g(d.this.f2671k);
            return d.this.f2671k.getApplicationContext().getCacheDir();
        }
    }

    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f2674a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private String f2675b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private n f2676c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private long f2677d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private long f2678e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private long f2679f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private j f2680g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private R.a f2681h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private R.c f2682i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private U.b f2683j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private boolean f2684k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private final Context f2685l;

        public d n() {
            return new d(this);
        }

        private b(Context context) {
            this.f2674a = 1;
            this.f2675b = "image_cache";
            this.f2677d = 41943040L;
            this.f2678e = 10485760L;
            this.f2679f = 2097152L;
            this.f2680g = new c();
            this.f2685l = context;
        }
    }

    protected d(b bVar) {
        Context context = bVar.f2685l;
        this.f2671k = context;
        X.k.j((bVar.f2676c == null && context == null) ? false : true, "Either a non-null context or a base directory path or supplier must be provided.");
        if (bVar.f2676c == null && context != null) {
            bVar.f2676c = new a();
        }
        this.f2661a = bVar.f2674a;
        this.f2662b = (String) X.k.g(bVar.f2675b);
        this.f2663c = (n) X.k.g(bVar.f2676c);
        this.f2664d = bVar.f2677d;
        this.f2665e = bVar.f2678e;
        this.f2666f = bVar.f2679f;
        this.f2667g = (j) X.k.g(bVar.f2680g);
        this.f2668h = bVar.f2681h == null ? R.g.b() : bVar.f2681h;
        this.f2669i = bVar.f2682i == null ? R.h.i() : bVar.f2682i;
        this.f2670j = bVar.f2683j == null ? U.c.b() : bVar.f2683j;
        this.f2672l = bVar.f2684k;
    }

    public static b m(Context context) {
        return new b(context);
    }

    public String b() {
        return this.f2662b;
    }

    public n c() {
        return this.f2663c;
    }

    public R.a d() {
        return this.f2668h;
    }

    public R.c e() {
        return this.f2669i;
    }

    public long f() {
        return this.f2664d;
    }

    public U.b g() {
        return this.f2670j;
    }

    public j h() {
        return this.f2667g;
    }

    public boolean i() {
        return this.f2672l;
    }

    public long j() {
        return this.f2665e;
    }

    public long k() {
        return this.f2666f;
    }

    public int l() {
        return this.f2661a;
    }
}
