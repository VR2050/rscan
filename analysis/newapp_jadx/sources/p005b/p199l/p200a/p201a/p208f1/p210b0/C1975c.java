package p005b.p199l.p200a.p201a.p208f1.p210b0;

import android.util.Pair;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p208f1.C2051r;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.b0.c */
/* loaded from: classes.dex */
public final class C1975c implements InterfaceC1977e {

    /* renamed from: a */
    public final long[] f3548a;

    /* renamed from: b */
    public final long[] f3549b;

    /* renamed from: c */
    public final long f3550c;

    public C1975c(long[] jArr, long[] jArr2) {
        this.f3548a = jArr;
        this.f3549b = jArr2;
        this.f3550c = C2399v.m2668a(jArr2[jArr2.length - 1]);
    }

    /* renamed from: d */
    public static Pair<Long, Long> m1504d(long j2, long[] jArr, long[] jArr2) {
        int m2326d = C2344d0.m2326d(jArr, j2, true, true);
        long j3 = jArr[m2326d];
        long j4 = jArr2[m2326d];
        int i2 = m2326d + 1;
        if (i2 == jArr.length) {
            return Pair.create(Long.valueOf(j3), Long.valueOf(j4));
        }
        return Pair.create(Long.valueOf(j2), Long.valueOf(((long) ((jArr[i2] == j3 ? ShadowDrawableWrapper.COS_45 : (j2 - j3) / (r6 - j3)) * (jArr2[i2] - j4))) + j4));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p210b0.InterfaceC1977e
    /* renamed from: a */
    public long mo1502a(long j2) {
        return C2399v.m2668a(((Long) m1504d(j2, this.f3548a, this.f3549b).second).longValue());
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p210b0.InterfaceC1977e
    /* renamed from: b */
    public long mo1503b() {
        return -1L;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        Pair<Long, Long> m1504d = m1504d(C2399v.m2669b(C2344d0.m2330h(j2, 0L, this.f3550c)), this.f3549b, this.f3548a);
        return new InterfaceC2050q.a(new C2051r(C2399v.m2668a(((Long) m1504d.first).longValue()), ((Long) m1504d.second).longValue()));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f3550c;
    }
}
