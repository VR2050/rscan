package p005b.p199l.p200a.p201a.p250p1;

import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.a.a.p1.o */
/* loaded from: classes.dex */
public final class C2355o {

    /* renamed from: a */
    public int f6106a;

    /* renamed from: b */
    public long[] f6107b = new long[32];

    /* renamed from: a */
    public void m2536a(long j2) {
        int i2 = this.f6106a;
        long[] jArr = this.f6107b;
        if (i2 == jArr.length) {
            this.f6107b = Arrays.copyOf(jArr, i2 * 2);
        }
        long[] jArr2 = this.f6107b;
        int i3 = this.f6106a;
        this.f6106a = i3 + 1;
        jArr2[i3] = j2;
    }

    /* renamed from: b */
    public long m2537b(int i2) {
        if (i2 >= 0 && i2 < this.f6106a) {
            return this.f6107b[i2];
        }
        StringBuilder m588J = C1499a.m588J("Invalid index ", i2, ", size is ");
        m588J.append(this.f6106a);
        throw new IndexOutOfBoundsException(m588J.toString());
    }
}
