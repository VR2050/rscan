package p005b.p199l.p200a.p201a.p208f1;

import java.util.Arrays;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.c */
/* loaded from: classes.dex */
public final class C1980c implements InterfaceC2050q {

    /* renamed from: a */
    public final int f3578a;

    /* renamed from: b */
    public final int[] f3579b;

    /* renamed from: c */
    public final long[] f3580c;

    /* renamed from: d */
    public final long[] f3581d;

    /* renamed from: e */
    public final long[] f3582e;

    /* renamed from: f */
    public final long f3583f;

    public C1980c(int[] iArr, long[] jArr, long[] jArr2, long[] jArr3) {
        this.f3579b = iArr;
        this.f3580c = jArr;
        this.f3581d = jArr2;
        this.f3582e = jArr3;
        int length = iArr.length;
        this.f3578a = length;
        if (length > 0) {
            this.f3583f = jArr2[length - 1] + jArr3[length - 1];
        } else {
            this.f3583f = 0L;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        int m2326d = C2344d0.m2326d(this.f3582e, j2, true, true);
        long[] jArr = this.f3582e;
        long j3 = jArr[m2326d];
        long[] jArr2 = this.f3580c;
        C2051r c2051r = new C2051r(j3, jArr2[m2326d]);
        if (j3 >= j2 || m2326d == this.f3578a - 1) {
            return new InterfaceC2050q.a(c2051r);
        }
        int i2 = m2326d + 1;
        return new InterfaceC2050q.a(c2051r, new C2051r(jArr[i2], jArr2[i2]));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f3583f;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ChunkIndex(length=");
        m586H.append(this.f3578a);
        m586H.append(", sizes=");
        m586H.append(Arrays.toString(this.f3579b));
        m586H.append(", offsets=");
        m586H.append(Arrays.toString(this.f3580c));
        m586H.append(", timeUs=");
        m586H.append(Arrays.toString(this.f3582e));
        m586H.append(", durationsUs=");
        m586H.append(Arrays.toString(this.f3581d));
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m586H.toString();
    }
}
