package p005b.p199l.p200a.p201a.p245m1;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.C2398u0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.m1.i */
/* loaded from: classes.dex */
public final class C2260i {

    /* renamed from: a */
    public final int f5663a;

    /* renamed from: b */
    public final C2398u0[] f5664b;

    /* renamed from: c */
    public final C2258g f5665c;

    /* renamed from: d */
    public final Object f5666d;

    public C2260i(C2398u0[] c2398u0Arr, InterfaceC2257f[] interfaceC2257fArr, Object obj) {
        this.f5664b = c2398u0Arr;
        this.f5665c = new C2258g(interfaceC2257fArr);
        this.f5666d = obj;
        this.f5663a = c2398u0Arr.length;
    }

    /* renamed from: a */
    public boolean m2165a(@Nullable C2260i c2260i, int i2) {
        return c2260i != null && C2344d0.m2323a(this.f5664b[i2], c2260i.f5664b[i2]) && C2344d0.m2323a(this.f5665c.f5660b[i2], c2260i.f5665c.f5660b[i2]);
    }

    /* renamed from: b */
    public boolean m2166b(int i2) {
        return this.f5664b[i2] != null;
    }
}
