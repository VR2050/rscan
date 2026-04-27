package n0;

import N0.l;
import e0.InterfaceC0512b;
import java.io.Closeable;
import s0.F;
import y0.C0722a;
import y0.C0731j;
import y0.EnumC0726e;
import y0.InterfaceC0723b;
import y0.InterfaceC0730i;
import y0.n;

/* JADX INFO: renamed from: n0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0633b extends C0722a implements Closeable, F {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final InterfaceC0512b f9678d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final C0731j f9679e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final InterfaceC0730i f9680f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private InterfaceC0730i f9681g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final boolean f9682h;

    public C0633b(InterfaceC0512b interfaceC0512b, C0731j c0731j, InterfaceC0730i interfaceC0730i) {
        this(interfaceC0512b, c0731j, interfaceC0730i, true);
    }

    private void P(C0731j c0731j, long j3) {
        c0731j.R(false);
        c0731j.L(j3);
        e0(c0731j, n.f10492g);
    }

    private void d0(C0731j c0731j, EnumC0726e enumC0726e) {
        c0731j.H(enumC0726e);
        this.f9680f.a(c0731j, enumC0726e);
        InterfaceC0730i interfaceC0730i = this.f9681g;
        if (interfaceC0730i != null) {
            interfaceC0730i.a(c0731j, enumC0726e);
        }
    }

    private void e0(C0731j c0731j, n nVar) {
        this.f9680f.b(c0731j, nVar);
        InterfaceC0730i interfaceC0730i = this.f9681g;
        if (interfaceC0730i != null) {
            interfaceC0730i.b(c0731j, nVar);
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    /* JADX INFO: renamed from: A, reason: merged with bridge method [inline-methods] */
    public void v(String str, l lVar, InterfaceC0723b.a aVar) {
        long jNow = this.f9678d.now();
        C0731j c0731j = this.f9679e;
        c0731j.F(aVar);
        c0731j.A(jNow);
        c0731j.J(jNow);
        c0731j.B(str);
        c0731j.G(lVar);
        d0(c0731j, EnumC0726e.f10396h);
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    /* JADX INFO: renamed from: D, reason: merged with bridge method [inline-methods] */
    public void b(String str, l lVar) {
        long jNow = this.f9678d.now();
        C0731j c0731j = this.f9679e;
        c0731j.C(jNow);
        c0731j.B(str);
        c0731j.G(lVar);
        d0(c0731j, EnumC0726e.f10395g);
    }

    public void W(C0731j c0731j, long j3) {
        c0731j.R(true);
        c0731j.Q(j3);
        e0(c0731j, n.f10491f);
    }

    public void Z() {
        this.f9679e.w();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        Z();
    }

    @Override // s0.F
    public void i(boolean z3) {
        if (z3) {
            W(this.f9679e, this.f9678d.now());
        } else {
            P(this.f9679e, this.f9678d.now());
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void p(String str, Object obj, InterfaceC0723b.a aVar) {
        long jNow = this.f9678d.now();
        C0731j c0731j = this.f9679e;
        c0731j.x();
        c0731j.D(jNow);
        c0731j.B(str);
        c0731j.y(obj);
        c0731j.F(aVar);
        d0(c0731j, EnumC0726e.f10394f);
        if (this.f9682h) {
            W(c0731j, jNow);
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void x(String str, InterfaceC0723b.a aVar) {
        long jNow = this.f9678d.now();
        C0731j c0731j = this.f9679e;
        c0731j.F(aVar);
        c0731j.B(str);
        d0(c0731j, EnumC0726e.f10399k);
        if (this.f9682h) {
            P(c0731j, jNow);
        }
    }

    @Override // y0.C0722a, y0.InterfaceC0723b
    public void y(String str, Throwable th, InterfaceC0723b.a aVar) {
        long jNow = this.f9678d.now();
        C0731j c0731j = this.f9679e;
        c0731j.F(aVar);
        c0731j.z(jNow);
        c0731j.B(str);
        c0731j.E(th);
        d0(c0731j, EnumC0726e.f10397i);
        P(c0731j, jNow);
    }

    public C0633b(InterfaceC0512b interfaceC0512b, C0731j c0731j, InterfaceC0730i interfaceC0730i, boolean z3) {
        this.f9681g = null;
        this.f9678d = interfaceC0512b;
        this.f9679e = c0731j;
        this.f9680f = interfaceC0730i;
        this.f9682h = z3;
    }

    @Override // s0.F
    public void onDraw() {
    }
}
