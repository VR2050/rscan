package I0;

import G0.C0175d;
import a0.InterfaceC0215a;
import a0.InterfaceC0223i;
import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetManager;
import android.content.res.Resources;
import com.facebook.imagepipeline.producers.C0356a;
import com.facebook.imagepipeline.producers.C0362g;
import com.facebook.imagepipeline.producers.C0363h;
import com.facebook.imagepipeline.producers.C0364i;
import com.facebook.imagepipeline.producers.C0365j;
import com.facebook.imagepipeline.producers.C0366k;
import com.facebook.imagepipeline.producers.C0367l;
import com.facebook.imagepipeline.producers.C0370o;
import com.facebook.imagepipeline.producers.C0371p;
import com.facebook.imagepipeline.producers.C0373s;
import com.facebook.imagepipeline.producers.C0376v;
import com.facebook.imagepipeline.producers.C0377w;
import com.facebook.imagepipeline.producers.C0379y;
import com.facebook.imagepipeline.producers.C0380z;
import com.facebook.imagepipeline.producers.LocalExifThumbnailProducer;
import com.facebook.imagepipeline.producers.X;
import com.facebook.imagepipeline.producers.Y;
import com.facebook.imagepipeline.producers.a0;
import com.facebook.imagepipeline.producers.b0;
import com.facebook.imagepipeline.producers.d0;
import com.facebook.imagepipeline.producers.i0;
import com.facebook.imagepipeline.producers.k0;
import com.facebook.imagepipeline.producers.n0;
import com.facebook.imagepipeline.producers.o0;
import com.facebook.imagepipeline.producers.p0;
import com.facebook.imagepipeline.producers.r0;
import com.facebook.imagepipeline.producers.t0;
import com.facebook.imagepipeline.producers.u0;

/* JADX INFO: loaded from: classes.dex */
public class C {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected ContentResolver f1109a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected Resources f1110b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected AssetManager f1111c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected final InterfaceC0215a f1112d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    protected final L0.c f1113e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected final L0.e f1114f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected final EnumC0189n f1115g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    protected final boolean f1116h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    protected final boolean f1117i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    protected final InterfaceC0191p f1118j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    protected final InterfaceC0223i f1119k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    protected final X.n f1120l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    protected final G0.x f1121m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    protected final G0.x f1122n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    protected final G0.k f1123o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    protected final C0175d f1124p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    protected final C0175d f1125q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    protected final F0.b f1126r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    protected final int f1127s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    protected final int f1128t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    protected boolean f1129u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    protected final C0176a f1130v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    protected final int f1131w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    protected final boolean f1132x;

    public C(Context context, InterfaceC0215a interfaceC0215a, L0.c cVar, L0.e eVar, EnumC0189n enumC0189n, boolean z3, boolean z4, InterfaceC0191p interfaceC0191p, InterfaceC0223i interfaceC0223i, G0.x xVar, G0.x xVar2, X.n nVar, G0.k kVar, F0.b bVar, int i3, int i4, boolean z5, int i5, C0176a c0176a, boolean z6, int i6) {
        this.f1109a = context.getApplicationContext().getContentResolver();
        this.f1110b = context.getApplicationContext().getResources();
        this.f1111c = context.getApplicationContext().getAssets();
        this.f1112d = interfaceC0215a;
        this.f1113e = cVar;
        this.f1114f = eVar;
        this.f1115g = enumC0189n;
        this.f1116h = z3;
        this.f1117i = z4;
        this.f1118j = interfaceC0191p;
        this.f1119k = interfaceC0223i;
        this.f1122n = xVar;
        this.f1121m = xVar2;
        this.f1120l = nVar;
        this.f1123o = kVar;
        this.f1126r = bVar;
        this.f1124p = new C0175d(i6);
        this.f1125q = new C0175d(i6);
        this.f1127s = i3;
        this.f1128t = i4;
        this.f1129u = z5;
        this.f1131w = i5;
        this.f1130v = c0176a;
        this.f1132x = z6;
    }

    public static C0356a a(d0 d0Var) {
        return new C0356a(d0Var);
    }

    public static C0367l h(d0 d0Var, d0 d0Var2) {
        return new C0367l(d0Var, d0Var2);
    }

    public a0 A(d0 d0Var) {
        return new a0(this.f1122n, this.f1123o, d0Var);
    }

    public b0 B(d0 d0Var) {
        return new b0(d0Var, this.f1126r, this.f1118j.e());
    }

    public i0 C() {
        return new i0(this.f1118j.c(), this.f1119k, this.f1109a);
    }

    public k0 D(d0 d0Var, boolean z3, V0.d dVar) {
        return new k0(this.f1118j.e(), this.f1119k, d0Var, z3, dVar);
    }

    public n0 E(d0 d0Var) {
        return new n0(d0Var);
    }

    public r0 F(d0 d0Var) {
        return new r0(5, this.f1118j.b(), d0Var);
    }

    public t0 G(u0[] u0VarArr) {
        return new t0(u0VarArr);
    }

    public d0 b(d0 d0Var, p0 p0Var) {
        return new o0(d0Var, p0Var);
    }

    public C0362g c(d0 d0Var) {
        return new C0362g(this.f1122n, this.f1123o, d0Var);
    }

    public C0363h d(d0 d0Var) {
        return new C0363h(this.f1123o, d0Var);
    }

    public C0364i e(d0 d0Var) {
        return new C0364i(this.f1122n, this.f1123o, d0Var);
    }

    public C0365j f(d0 d0Var) {
        return new C0365j(d0Var, this.f1127s, this.f1128t, this.f1129u);
    }

    public C0366k g(d0 d0Var) {
        return new C0366k(this.f1121m, this.f1120l, this.f1123o, this.f1124p, this.f1125q, d0Var);
    }

    public C0370o i() {
        return new C0370o(this.f1119k);
    }

    public C0371p j(d0 d0Var) {
        return new C0371p(this.f1112d, this.f1118j.a(), this.f1113e, this.f1114f, this.f1115g, this.f1116h, this.f1117i, d0Var, this.f1131w, this.f1130v, null, X.o.f2853b);
    }

    public C0373s k(d0 d0Var) {
        return new C0373s(d0Var, this.f1118j.g());
    }

    public C0376v l(d0 d0Var) {
        return new C0376v(this.f1120l, this.f1123o, d0Var);
    }

    public C0377w m(d0 d0Var) {
        return new C0377w(this.f1120l, this.f1123o, d0Var);
    }

    public C0379y n(d0 d0Var) {
        return new C0379y(this.f1123o, this.f1132x, d0Var);
    }

    public d0 o(d0 d0Var) {
        return new C0380z(this.f1121m, this.f1123o, d0Var);
    }

    public com.facebook.imagepipeline.producers.A p(d0 d0Var) {
        return new com.facebook.imagepipeline.producers.A(this.f1120l, this.f1123o, this.f1124p, this.f1125q, d0Var);
    }

    public com.facebook.imagepipeline.producers.H q() {
        return new com.facebook.imagepipeline.producers.H(this.f1118j.c(), this.f1119k, this.f1111c);
    }

    public com.facebook.imagepipeline.producers.I r() {
        return new com.facebook.imagepipeline.producers.I(this.f1118j.c(), this.f1119k, this.f1109a);
    }

    public com.facebook.imagepipeline.producers.J s() {
        return new com.facebook.imagepipeline.producers.J(this.f1118j.c(), this.f1119k, this.f1109a);
    }

    public LocalExifThumbnailProducer t() {
        return new LocalExifThumbnailProducer(this.f1118j.d(), this.f1119k, this.f1109a);
    }

    public com.facebook.imagepipeline.producers.M u() {
        return new com.facebook.imagepipeline.producers.M(this.f1118j.c(), this.f1119k);
    }

    public com.facebook.imagepipeline.producers.N v() {
        return new com.facebook.imagepipeline.producers.N(this.f1118j.c(), this.f1119k, this.f1110b);
    }

    public com.facebook.imagepipeline.producers.S w() {
        return new com.facebook.imagepipeline.producers.S(this.f1118j.e(), this.f1109a);
    }

    public com.facebook.imagepipeline.producers.T x() {
        return new com.facebook.imagepipeline.producers.T(this.f1118j.c(), this.f1109a);
    }

    public d0 y(X x3) {
        return new com.facebook.imagepipeline.producers.W(this.f1119k, this.f1112d, x3);
    }

    public Y z(d0 d0Var) {
        return new Y(this.f1120l, this.f1123o, this.f1119k, this.f1112d, d0Var);
    }
}
