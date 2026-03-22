package p005b.p199l.p200a.p201a.p227k1.p230l0;

import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p220h1.p221g.C2085b;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2148e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.l0.i */
/* loaded from: classes.dex */
public final class C2142i implements InterfaceC2107e0 {

    /* renamed from: c */
    public final Format f4750c;

    /* renamed from: f */
    public long[] f4752f;

    /* renamed from: g */
    public boolean f4753g;

    /* renamed from: h */
    public C2148e f4754h;

    /* renamed from: i */
    public boolean f4755i;

    /* renamed from: j */
    public int f4756j;

    /* renamed from: e */
    public final C2085b f4751e = new C2085b();

    /* renamed from: k */
    public long f4757k = -9223372036854775807L;

    public C2142i(C2148e c2148e, Format format, boolean z) {
        this.f4750c = format;
        this.f4754h = c2148e;
        this.f4752f = c2148e.f4807b;
        m1885c(c2148e, z);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: a */
    public void mo1786a() {
    }

    /* renamed from: b */
    public void m1884b(long j2) {
        int m2324b = C2344d0.m2324b(this.f4752f, j2, true, false);
        this.f4756j = m2324b;
        if (!(this.f4753g && m2324b == this.f4752f.length)) {
            j2 = -9223372036854775807L;
        }
        this.f4757k = j2;
    }

    /* renamed from: c */
    public void m1885c(C2148e c2148e, boolean z) {
        int i2 = this.f4756j;
        long j2 = i2 == 0 ? -9223372036854775807L : this.f4752f[i2 - 1];
        this.f4753g = z;
        this.f4754h = c2148e;
        long[] jArr = c2148e.f4807b;
        this.f4752f = jArr;
        long j3 = this.f4757k;
        if (j3 != -9223372036854775807L) {
            m1884b(j3);
        } else if (j2 != -9223372036854775807L) {
            this.f4756j = C2344d0.m2324b(jArr, j2, false, false);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: i */
    public int mo1787i(C1964f0 c1964f0, C1945e c1945e, boolean z) {
        if (z || !this.f4755i) {
            c1964f0.f3394c = this.f4750c;
            this.f4755i = true;
            return -5;
        }
        int i2 = this.f4756j;
        if (i2 == this.f4752f.length) {
            if (this.f4753g) {
                return -3;
            }
            c1945e.setFlags(4);
            return -4;
        }
        this.f4756j = i2 + 1;
        byte[] m1711a = this.f4751e.m1711a(this.f4754h.f4806a[i2]);
        if (m1711a == null) {
            return -3;
        }
        c1945e.m1381f(m1711a.length);
        c1945e.f3306e.put(m1711a);
        c1945e.f3307f = this.f4752f[i2];
        c1945e.setFlags(1);
        return -4;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    public boolean isReady() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: o */
    public int mo1788o(long j2) {
        int max = Math.max(this.f4756j, C2344d0.m2324b(this.f4752f, j2, true, false));
        int i2 = max - this.f4756j;
        this.f4756j = max;
        return i2;
    }
}
