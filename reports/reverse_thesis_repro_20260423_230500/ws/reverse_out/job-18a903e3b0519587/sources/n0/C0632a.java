package n0;

import e0.InterfaceC0512b;
import y0.C0731j;

/* JADX INFO: renamed from: n0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0632a extends P0.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final InterfaceC0512b f9676a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0731j f9677b;

    public C0632a(InterfaceC0512b interfaceC0512b, C0731j c0731j) {
        this.f9676a = interfaceC0512b;
        this.f9677b = c0731j;
    }

    @Override // P0.e
    public void a(T0.b bVar, String str, Throwable th, boolean z3) {
        this.f9677b.J(this.f9676a.now());
        this.f9677b.I(bVar);
        this.f9677b.P(str);
        this.f9677b.O(z3);
    }

    @Override // P0.e
    public void b(T0.b bVar, Object obj, String str, boolean z3) {
        this.f9677b.K(this.f9676a.now());
        this.f9677b.I(bVar);
        this.f9677b.y(obj);
        this.f9677b.P(str);
        this.f9677b.O(z3);
    }

    @Override // P0.e
    public void d(T0.b bVar, String str, boolean z3) {
        this.f9677b.J(this.f9676a.now());
        this.f9677b.I(bVar);
        this.f9677b.P(str);
        this.f9677b.O(z3);
    }

    @Override // P0.e
    public void j(String str) {
        this.f9677b.J(this.f9676a.now());
        this.f9677b.P(str);
    }
}
