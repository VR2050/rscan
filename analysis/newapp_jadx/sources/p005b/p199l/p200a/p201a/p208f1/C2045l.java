package p005b.p199l.p200a.p201a.p208f1;

import java.util.Objects;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2353m;

/* renamed from: b.l.a.a.f1.l */
/* loaded from: classes.dex */
public final class C2045l implements InterfaceC2050q {

    /* renamed from: a */
    public final C2353m f4167a;

    /* renamed from: b */
    public final long f4168b;

    public C2045l(C2353m c2353m, long j2) {
        this.f4167a = c2353m;
        this.f4168b = j2;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return true;
    }

    /* renamed from: d */
    public final C2051r m1629d(long j2, long j3) {
        return new C2051r((j2 * 1000000) / this.f4167a.f6077e, this.f4168b + j3);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        Objects.requireNonNull(this.f4167a.f6083k);
        C2353m c2353m = this.f4167a;
        C2353m.a aVar = c2353m.f6083k;
        long[] jArr = aVar.f6085a;
        long[] jArr2 = aVar.f6086b;
        int m2326d = C2344d0.m2326d(jArr, c2353m.m2373g(j2), true, false);
        C2051r m1629d = m1629d(m2326d == -1 ? 0L : jArr[m2326d], m2326d != -1 ? jArr2[m2326d] : 0L);
        if (m1629d.f4193b == j2 || m2326d == jArr.length - 1) {
            return new InterfaceC2050q.a(m1629d);
        }
        int i2 = m2326d + 1;
        return new InterfaceC2050q.a(m1629d, m1629d(jArr[i2], jArr2[i2]));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f4167a.m2370d();
    }
}
