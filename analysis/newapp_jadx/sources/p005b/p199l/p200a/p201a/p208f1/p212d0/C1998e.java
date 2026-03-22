package p005b.p199l.p200a.p201a.p208f1.p212d0;

import java.io.EOFException;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.d0.e */
/* loaded from: classes.dex */
public final class C1998e {

    /* renamed from: a */
    public int f3752a;

    /* renamed from: b */
    public int f3753b;

    /* renamed from: c */
    public long f3754c;

    /* renamed from: d */
    public int f3755d;

    /* renamed from: e */
    public int f3756e;

    /* renamed from: f */
    public int f3757f;

    /* renamed from: g */
    public final int[] f3758g = new int[255];

    /* renamed from: h */
    public final C2360t f3759h = new C2360t(255);

    /* renamed from: a */
    public boolean m1556a(C2003e c2003e, boolean z) {
        this.f3759h.m2592x();
        m1557b();
        long j2 = c2003e.f3788c;
        if (!(j2 == -1 || j2 - c2003e.m1564d() >= 27) || !c2003e.m1565e(this.f3759h.f6133a, 0, 27, true)) {
            if (z) {
                return false;
            }
            throw new EOFException();
        }
        if (this.f3759h.m2586r() != 1332176723) {
            if (z) {
                return false;
            }
            throw new C2205l0("expected OggS capture pattern at begin of page");
        }
        int m2585q = this.f3759h.m2585q();
        this.f3752a = m2585q;
        if (m2585q != 0) {
            if (z) {
                return false;
            }
            throw new C2205l0("unsupported bit stream revision");
        }
        this.f3753b = this.f3759h.m2585q();
        C2360t c2360t = this.f3759h;
        byte[] bArr = c2360t.f6133a;
        int i2 = c2360t.f6134b + 1;
        c2360t.f6134b = i2;
        long j3 = bArr[r2] & 255;
        int i3 = i2 + 1;
        c2360t.f6134b = i3;
        long j4 = j3 | ((bArr[i2] & 255) << 8);
        int i4 = i3 + 1;
        c2360t.f6134b = i4;
        long j5 = j4 | ((bArr[i3] & 255) << 16);
        int i5 = i4 + 1;
        c2360t.f6134b = i5;
        long j6 = j5 | ((bArr[i4] & 255) << 24);
        int i6 = i5 + 1;
        c2360t.f6134b = i6;
        long j7 = j6 | ((bArr[i5] & 255) << 32);
        int i7 = i6 + 1;
        c2360t.f6134b = i7;
        long j8 = j7 | ((bArr[i6] & 255) << 40);
        int i8 = i7 + 1;
        c2360t.f6134b = i8;
        c2360t.f6134b = i8 + 1;
        this.f3754c = ((bArr[i8] & 255) << 56) | j8 | ((bArr[i7] & 255) << 48);
        c2360t.m2576h();
        this.f3759h.m2576h();
        this.f3759h.m2576h();
        int m2585q2 = this.f3759h.m2585q();
        this.f3755d = m2585q2;
        this.f3756e = m2585q2 + 27;
        this.f3759h.m2592x();
        c2003e.m1565e(this.f3759h.f6133a, 0, this.f3755d, false);
        for (int i9 = 0; i9 < this.f3755d; i9++) {
            this.f3758g[i9] = this.f3759h.m2585q();
            this.f3757f += this.f3758g[i9];
        }
        return true;
    }

    /* renamed from: b */
    public void m1557b() {
        this.f3752a = 0;
        this.f3753b = 0;
        this.f3754c = 0L;
        this.f3755d = 0;
        this.f3756e = 0;
        this.f3757f = 0;
    }
}
