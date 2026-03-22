package p005b.p199l.p200a.p201a.p208f1.p210b0;

import p005b.p199l.p200a.p201a.p208f1.C2051r;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.b0.f */
/* loaded from: classes.dex */
public final class C1978f implements InterfaceC1977e {

    /* renamed from: a */
    public final long[] f3568a;

    /* renamed from: b */
    public final long[] f3569b;

    /* renamed from: c */
    public final long f3570c;

    /* renamed from: d */
    public final long f3571d;

    public C1978f(long[] jArr, long[] jArr2, long j2, long j3) {
        this.f3568a = jArr;
        this.f3569b = jArr2;
        this.f3570c = j2;
        this.f3571d = j3;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p210b0.InterfaceC1977e
    /* renamed from: a */
    public long mo1502a(long j2) {
        return this.f3568a[C2344d0.m2326d(this.f3569b, j2, true, true)];
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p210b0.InterfaceC1977e
    /* renamed from: b */
    public long mo1503b() {
        return this.f3571d;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        int m2326d = C2344d0.m2326d(this.f3568a, j2, true, true);
        long[] jArr = this.f3568a;
        long j3 = jArr[m2326d];
        long[] jArr2 = this.f3569b;
        C2051r c2051r = new C2051r(j3, jArr2[m2326d]);
        if (j3 >= j2 || m2326d == jArr.length - 1) {
            return new InterfaceC2050q.a(c2051r);
        }
        int i2 = m2326d + 1;
        return new InterfaceC2050q.a(c2051r, new C2051r(jArr[i2], jArr2[i2]));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f3570c;
    }
}
