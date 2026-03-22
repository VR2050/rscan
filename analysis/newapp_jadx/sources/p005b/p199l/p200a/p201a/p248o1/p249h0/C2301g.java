package p005b.p199l.p200a.p201a.p248o1.p249h0;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p248o1.C2332x;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2319k;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;

/* renamed from: b.l.a.a.o1.h0.g */
/* loaded from: classes.dex */
public final class C2301g implements InterfaceC2321m.a {

    /* renamed from: a */
    public final InterfaceC2297c f5857a;

    /* renamed from: b */
    public final InterfaceC2321m.a f5858b;

    /* renamed from: c */
    public final InterfaceC2321m.a f5859c;

    /* renamed from: d */
    @Nullable
    public final InterfaceC2319k.a f5860d;

    public C2301g(InterfaceC2297c interfaceC2297c, InterfaceC2321m.a aVar, int i2) {
        C2332x.a aVar2 = new C2332x.a();
        C2299e c2299e = new C2299e(interfaceC2297c, 5242880L);
        this.f5857a = interfaceC2297c;
        this.f5858b = aVar;
        this.f5859c = aVar2;
        this.f5860d = c2299e;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m.a
    public InterfaceC2321m createDataSource() {
        InterfaceC2297c interfaceC2297c = this.f5857a;
        InterfaceC2321m createDataSource = this.f5858b.createDataSource();
        InterfaceC2321m createDataSource2 = this.f5859c.createDataSource();
        InterfaceC2319k.a aVar = this.f5860d;
        return new C2300f(interfaceC2297c, createDataSource, createDataSource2, aVar == null ? null : new C2298d(((C2299e) aVar).f5831a, 5242880L, 20480), 2, null, null);
    }
}
