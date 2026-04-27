package t0;

import X.k;
import android.content.res.Resources;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.PointF;
import android.graphics.drawable.Drawable;
import java.util.Iterator;
import java.util.List;
import s0.q;

/* JADX INFO: renamed from: t0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0691b {

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    public static final q f10142t = q.f10121h;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    public static final q f10143u = q.f10122i;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Resources f10144a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f10145b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f10146c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Drawable f10147d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private q f10148e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Drawable f10149f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private q f10150g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Drawable f10151h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private q f10152i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private Drawable f10153j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private q f10154k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private q f10155l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private Matrix f10156m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private PointF f10157n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private ColorFilter f10158o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private Drawable f10159p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private List f10160q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private Drawable f10161r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private C0693d f10162s;

    public C0691b(Resources resources) {
        this.f10144a = resources;
        s();
    }

    private void s() {
        this.f10145b = 300;
        this.f10146c = 0.0f;
        this.f10147d = null;
        q qVar = f10142t;
        this.f10148e = qVar;
        this.f10149f = null;
        this.f10150g = qVar;
        this.f10151h = null;
        this.f10152i = qVar;
        this.f10153j = null;
        this.f10154k = qVar;
        this.f10155l = f10143u;
        this.f10156m = null;
        this.f10157n = null;
        this.f10158o = null;
        this.f10159p = null;
        this.f10160q = null;
        this.f10161r = null;
        this.f10162s = null;
    }

    public static C0691b t(Resources resources) {
        return new C0691b(resources);
    }

    private void v() {
        List list = this.f10160q;
        if (list != null) {
            Iterator it = list.iterator();
            while (it.hasNext()) {
                k.g((Drawable) it.next());
            }
        }
    }

    public C0690a a() {
        v();
        return new C0690a(this);
    }

    public ColorFilter b() {
        return this.f10158o;
    }

    public PointF c() {
        return this.f10157n;
    }

    public q d() {
        return this.f10155l;
    }

    public Drawable e() {
        return this.f10159p;
    }

    public int f() {
        return this.f10145b;
    }

    public Drawable g() {
        return this.f10151h;
    }

    public q h() {
        return this.f10152i;
    }

    public List i() {
        return this.f10160q;
    }

    public Drawable j() {
        return this.f10147d;
    }

    public q k() {
        return this.f10148e;
    }

    public Drawable l() {
        return this.f10161r;
    }

    public Drawable m() {
        return this.f10153j;
    }

    public q n() {
        return this.f10154k;
    }

    public Resources o() {
        return this.f10144a;
    }

    public Drawable p() {
        return this.f10149f;
    }

    public q q() {
        return this.f10150g;
    }

    public C0693d r() {
        return this.f10162s;
    }

    public C0691b u(C0693d c0693d) {
        this.f10162s = c0693d;
        return this;
    }
}
