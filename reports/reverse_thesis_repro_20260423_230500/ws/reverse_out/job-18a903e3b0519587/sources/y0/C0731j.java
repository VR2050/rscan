package y0;

import i2.AbstractC0586n;
import y0.InterfaceC0723b;

/* JADX INFO: renamed from: y0.j, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0731j extends AbstractC0729h {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private long f10461A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private long f10462B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private long f10463C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private boolean f10464D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private int f10465E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private int f10466F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private Throwable f10467G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private EnumC0726e f10468H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private n f10469I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private long f10470J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private long f10471K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private InterfaceC0723b.a f10472L;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private String f10473s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private String f10474t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private Object f10475u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private Object f10476v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private Object f10477w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private long f10478x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private long f10479y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private long f10480z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0731j(EnumC0732k enumC0732k) {
        super(enumC0732k);
        t2.j.f(enumC0732k, "infra");
        this.f10478x = -1L;
        this.f10479y = -1L;
        this.f10480z = -1L;
        this.f10461A = -1L;
        this.f10462B = -1L;
        this.f10463C = -1L;
        this.f10465E = -1;
        this.f10466F = -1;
        this.f10468H = EnumC0726e.f10393e;
        this.f10469I = n.f10490e;
        this.f10470J = -1L;
        this.f10471K = -1L;
    }

    public final void A(long j3) {
        this.f10480z = j3;
    }

    public final void B(String str) {
        this.f10473s = str;
    }

    public final void C(long j3) {
        this.f10479y = j3;
    }

    public final void D(long j3) {
        this.f10478x = j3;
    }

    public final void E(Throwable th) {
        this.f10467G = th;
    }

    public final void F(InterfaceC0723b.a aVar) {
        this.f10472L = aVar;
    }

    public final void G(Object obj) {
        this.f10477w = obj;
    }

    public final void H(EnumC0726e enumC0726e) {
        t2.j.f(enumC0726e, "<set-?>");
        this.f10468H = enumC0726e;
    }

    public final void I(Object obj) {
        this.f10475u = obj;
    }

    public final void J(long j3) {
        this.f10463C = j3;
    }

    public final void K(long j3) {
        this.f10462B = j3;
    }

    public final void L(long j3) {
        this.f10471K = j3;
    }

    public final void M(int i3) {
        this.f10466F = i3;
    }

    public final void N(int i3) {
        this.f10465E = i3;
    }

    public final void O(boolean z3) {
        this.f10464D = z3;
    }

    public final void P(String str) {
        this.f10474t = str;
    }

    public final void Q(long j3) {
        this.f10470J = j3;
    }

    public final void R(boolean z3) {
        this.f10469I = z3 ? n.f10491f : n.f10492g;
    }

    public final C0727f S() {
        return new C0727f(j(), this.f10473s, this.f10474t, this.f10475u, this.f10476v, this.f10477w, this.f10478x, this.f10479y, this.f10480z, this.f10461A, this.f10462B, this.f10463C, f(), n(), this.f10464D, this.f10465E, this.f10466F, this.f10467G, this.f10469I, this.f10470J, this.f10471K, null, this.f10472L, a(), o(), c(), d(), b(), r(), q(), l(), p(), AbstractC0586n.T(k()), m(), h(), i(), g(), e());
    }

    public final void w() {
        this.f10474t = null;
        this.f10475u = null;
        this.f10476v = null;
        this.f10477w = null;
        this.f10464D = false;
        this.f10465E = -1;
        this.f10466F = -1;
        this.f10467G = null;
        this.f10468H = EnumC0726e.f10393e;
        this.f10469I = n.f10490e;
        this.f10472L = null;
        x();
        s();
    }

    public final void x() {
        this.f10462B = -1L;
        this.f10463C = -1L;
        this.f10478x = -1L;
        this.f10480z = -1L;
        this.f10461A = -1L;
        this.f10470J = -1L;
        this.f10471K = -1L;
        k().clear();
        u(false);
        t(null);
        v(null);
    }

    public final void y(Object obj) {
        this.f10476v = obj;
    }

    public final void z(long j3) {
        this.f10461A = j3;
    }
}
