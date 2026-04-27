package T0;

import H0.f;
import H0.g;
import H0.h;
import I0.C0195u;
import I0.EnumC0189n;
import P0.e;
import T0.b;
import X.k;
import android.net.Uri;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public class c {

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private static final Set f2779t = new HashSet();

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private e f2793n;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f2797r;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Uri f2780a = null;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private b.c f2781b = b.c.FULL_FETCH;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f2782c = 0;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private g f2783d = null;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private h f2784e = null;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private H0.d f2785f = H0.d.a();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private b.EnumC0041b f2786g = b.EnumC0041b.DEFAULT;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f2787h = C0195u.b().a();

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f2788i = false;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f2789j = false;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private f f2790k = f.f1017e;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private d f2791l = null;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private Boolean f2792m = null;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private H0.b f2794o = null;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private Boolean f2795p = null;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private EnumC0189n f2796q = null;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private String f2798s = null;

    public static class a extends RuntimeException {
        public a(String str) {
            super("Invalid request builder: " + str);
        }
    }

    private c() {
    }

    private c B(int i3) {
        this.f2782c = i3;
        if (this.f2786g != b.EnumC0041b.DYNAMIC) {
            this.f2798s = null;
        }
        return this;
    }

    public static c b(b bVar) {
        return x(bVar.v()).F(bVar.h()).z(bVar.b()).A(bVar.c()).H(bVar.j()).G(bVar.i()).I(bVar.k()).B(bVar.d()).J(bVar.l()).K(bVar.p()).M(bVar.o()).N(bVar.r()).L(bVar.q()).P(bVar.t()).Q(bVar.z()).C(bVar.e()).D(bVar.f()).E(bVar.g()).O(bVar.s());
    }

    public static boolean s(Uri uri) {
        Set set = f2779t;
        if (set != null && uri != null) {
            Iterator it = set.iterator();
            while (it.hasNext()) {
                if (((String) it.next()).equals(uri.getScheme())) {
                    return true;
                }
            }
        }
        return false;
    }

    public static c x(Uri uri) {
        return new c().R(uri);
    }

    public c A(b.EnumC0041b enumC0041b) {
        this.f2786g = enumC0041b;
        return this;
    }

    public c C(int i3) {
        this.f2797r = i3;
        return this;
    }

    public c D(String str) {
        this.f2798s = str;
        return this;
    }

    public c E(EnumC0189n enumC0189n) {
        this.f2796q = enumC0189n;
        return this;
    }

    public c F(H0.d dVar) {
        this.f2785f = dVar;
        return this;
    }

    public c G(boolean z3) {
        this.f2789j = z3;
        return this;
    }

    public c H(boolean z3) {
        this.f2788i = z3;
        return this;
    }

    public c I(b.c cVar) {
        this.f2781b = cVar;
        return this;
    }

    public c J(d dVar) {
        this.f2791l = dVar;
        return this;
    }

    public c K(boolean z3) {
        this.f2787h = z3;
        return this;
    }

    public c L(e eVar) {
        this.f2793n = eVar;
        return this;
    }

    public c M(f fVar) {
        this.f2790k = fVar;
        return this;
    }

    public c N(g gVar) {
        this.f2783d = gVar;
        return this;
    }

    public c O(Boolean bool) {
        this.f2795p = bool;
        return this;
    }

    public c P(h hVar) {
        this.f2784e = hVar;
        return this;
    }

    public c Q(Boolean bool) {
        this.f2792m = bool;
        return this;
    }

    public c R(Uri uri) {
        k.g(uri);
        this.f2780a = uri;
        return this;
    }

    public Boolean S() {
        return this.f2792m;
    }

    protected void T() {
        Uri uri = this.f2780a;
        if (uri == null) {
            throw new a("Source must be set!");
        }
        if (f0.f.m(uri)) {
            if (!this.f2780a.isAbsolute()) {
                throw new a("Resource URI path must be absolute.");
            }
            if (this.f2780a.getPath().isEmpty()) {
                throw new a("Resource URI must not be empty");
            }
            try {
                Integer.parseInt(this.f2780a.getPath().substring(1));
            } catch (NumberFormatException unused) {
                throw new a("Resource URI path must be a resource id.");
            }
        }
        if (f0.f.h(this.f2780a) && !this.f2780a.isAbsolute()) {
            throw new a("Asset URI path must be absolute.");
        }
    }

    public b a() {
        T();
        return new b(this);
    }

    public H0.b c() {
        return this.f2794o;
    }

    public b.EnumC0041b d() {
        return this.f2786g;
    }

    public int e() {
        return this.f2782c;
    }

    public int f() {
        return this.f2797r;
    }

    public String g() {
        return this.f2798s;
    }

    public EnumC0189n h() {
        return this.f2796q;
    }

    public H0.d i() {
        return this.f2785f;
    }

    public boolean j() {
        return this.f2789j;
    }

    public b.c k() {
        return this.f2781b;
    }

    public d l() {
        return this.f2791l;
    }

    public e m() {
        return this.f2793n;
    }

    public f n() {
        return this.f2790k;
    }

    public g o() {
        return this.f2783d;
    }

    public Boolean p() {
        return this.f2795p;
    }

    public h q() {
        return this.f2784e;
    }

    public Uri r() {
        return this.f2780a;
    }

    public boolean t() {
        return (this.f2782c & 48) == 0 && (f0.f.n(this.f2780a) || s(this.f2780a));
    }

    public boolean u() {
        return this.f2788i;
    }

    public boolean v() {
        return (this.f2782c & 15) == 0;
    }

    public boolean w() {
        return this.f2787h;
    }

    public c y(boolean z3) {
        return z3 ? P(h.c()) : P(h.e());
    }

    public c z(H0.b bVar) {
        this.f2794o = bVar;
        return this;
    }
}
