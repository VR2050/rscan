package p005b.p199l.p200a.p201a.p208f1.p209a0;

import p005b.p199l.p200a.p201a.p208f1.C2003e;

/* renamed from: b.l.a.a.f1.a0.f */
/* loaded from: classes.dex */
public final class C1971f {

    /* renamed from: a */
    public static final long[] f3543a = {128, 64, 32, 16, 8, 4, 2, 1};

    /* renamed from: b */
    public final byte[] f3544b = new byte[8];

    /* renamed from: c */
    public int f3545c;

    /* renamed from: d */
    public int f3546d;

    /* renamed from: a */
    public static long m1497a(byte[] bArr, int i2, boolean z) {
        long j2 = bArr[0] & 255;
        if (z) {
            j2 &= ~f3543a[i2 - 1];
        }
        for (int i3 = 1; i3 < i2; i3++) {
            j2 = (j2 << 8) | (bArr[i3] & 255);
        }
        return j2;
    }

    /* renamed from: b */
    public static int m1498b(int i2) {
        int i3 = 0;
        while (true) {
            long[] jArr = f3543a;
            if (i3 >= jArr.length) {
                return -1;
            }
            if ((jArr[i3] & i2) != 0) {
                return i3 + 1;
            }
            i3++;
        }
    }

    /* renamed from: c */
    public long m1499c(C2003e c2003e, boolean z, boolean z2, int i2) {
        if (this.f3545c == 0) {
            if (!c2003e.m1568h(this.f3544b, 0, 1, z)) {
                return -1L;
            }
            int m1498b = m1498b(this.f3544b[0] & 255);
            this.f3546d = m1498b;
            if (m1498b == -1) {
                throw new IllegalStateException("No valid varint length mask found");
            }
            this.f3545c = 1;
        }
        int i3 = this.f3546d;
        if (i3 > i2) {
            this.f3545c = 0;
            return -2L;
        }
        if (i3 != 1) {
            c2003e.m1568h(this.f3544b, 1, i3 - 1, false);
        }
        this.f3545c = 0;
        return m1497a(this.f3544b, this.f3546d, z2);
    }
}
