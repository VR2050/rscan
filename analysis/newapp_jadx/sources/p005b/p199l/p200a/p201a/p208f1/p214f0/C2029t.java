package p005b.p199l.p200a.p201a.p208f1.p214f0;

import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.t */
/* loaded from: classes.dex */
public final class C2029t {

    /* renamed from: c */
    public boolean f4087c;

    /* renamed from: d */
    public boolean f4088d;

    /* renamed from: e */
    public boolean f4089e;

    /* renamed from: a */
    public final C2342c0 f4085a = new C2342c0(0);

    /* renamed from: f */
    public long f4090f = -9223372036854775807L;

    /* renamed from: g */
    public long f4091g = -9223372036854775807L;

    /* renamed from: h */
    public long f4092h = -9223372036854775807L;

    /* renamed from: b */
    public final C2360t f4086b = new C2360t();

    /* renamed from: c */
    public static long m1608c(C2360t c2360t) {
        int i2 = c2360t.f6134b;
        if (c2360t.m2569a() < 9) {
            return -9223372036854775807L;
        }
        byte[] bArr = new byte[9];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, 9);
        c2360t.f6134b += 9;
        c2360t.m2567C(i2);
        if ((bArr[0] & 196) == 68 && (bArr[2] & 4) == 4 && (bArr[4] & 4) == 4 && (bArr[5] & 1) == 1 && (bArr[8] & 3) == 3) {
            return (((bArr[0] & 56) >> 3) << 30) | ((bArr[0] & 3) << 28) | ((bArr[1] & 255) << 20) | (((bArr[2] & 248) >> 3) << 15) | ((bArr[2] & 3) << 13) | ((bArr[3] & 255) << 5) | ((bArr[4] & 248) >> 3);
        }
        return -9223372036854775807L;
    }

    /* renamed from: a */
    public final int m1609a(C2003e c2003e) {
        this.f4086b.m2594z(C2344d0.f6040f);
        this.f4087c = true;
        c2003e.f3791f = 0;
        return 0;
    }

    /* renamed from: b */
    public final int m1610b(byte[] bArr, int i2) {
        return (bArr[i2 + 3] & 255) | ((bArr[i2] & 255) << 24) | ((bArr[i2 + 1] & 255) << 16) | ((bArr[i2 + 2] & 255) << 8);
    }
}
