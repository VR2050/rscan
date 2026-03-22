package p005b.p199l.p200a.p201a.p208f1.p218z;

import com.google.android.exoplayer2.Format;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d;
import p005b.p199l.p200a.p201a.p250p1.C2358r;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p005b.p199l.p200a.p201a.p251q1.C2376h;

/* renamed from: b.l.a.a.f1.z.e */
/* loaded from: classes.dex */
public final class C2065e extends AbstractC2064d {

    /* renamed from: b */
    public final C2360t f4269b;

    /* renamed from: c */
    public final C2360t f4270c;

    /* renamed from: d */
    public int f4271d;

    /* renamed from: e */
    public boolean f4272e;

    /* renamed from: f */
    public boolean f4273f;

    /* renamed from: g */
    public int f4274g;

    public C2065e(InterfaceC2052s interfaceC2052s) {
        super(interfaceC2052s);
        this.f4269b = new C2360t(C2358r.f6109a);
        this.f4270c = new C2360t(4);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d
    /* renamed from: b */
    public boolean mo1644b(C2360t c2360t) {
        int m2585q = c2360t.m2585q();
        int i2 = (m2585q >> 4) & 15;
        int i3 = m2585q & 15;
        if (i3 != 7) {
            throw new AbstractC2064d.a(C1499a.m626l("Video format not supported: ", i3));
        }
        this.f4274g = i2;
        return i2 != 5;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d
    /* renamed from: c */
    public boolean mo1645c(C2360t c2360t, long j2) {
        int m2585q = c2360t.m2585q();
        byte[] bArr = c2360t.f6133a;
        int i2 = c2360t.f6134b;
        int i3 = i2 + 1;
        c2360t.f6134b = i3;
        int i4 = ((bArr[i2] & 255) << 24) >> 8;
        int i5 = i3 + 1;
        c2360t.f6134b = i5;
        int i6 = i4 | ((bArr[i3] & 255) << 8);
        c2360t.f6134b = i5 + 1;
        long j3 = (((bArr[i5] & 255) | i6) * 1000) + j2;
        if (m2585q == 0 && !this.f4272e) {
            C2360t c2360t2 = new C2360t(new byte[c2360t.m2569a()]);
            c2360t.m2572d(c2360t2.f6133a, 0, c2360t.m2569a());
            C2376h m2614b = C2376h.m2614b(c2360t2);
            this.f4271d = m2614b.f6179b;
            this.f4268a.mo1615d(Format.m4034K(null, "video/avc", null, -1, -1, m2614b.f6180c, m2614b.f6181d, -1.0f, m2614b.f6178a, -1, m2614b.f6182e, null));
            this.f4272e = true;
            return false;
        }
        if (m2585q != 1 || !this.f4272e) {
            return false;
        }
        int i7 = this.f4274g == 1 ? 1 : 0;
        if (!this.f4273f && i7 == 0) {
            return false;
        }
        byte[] bArr2 = this.f4270c.f6133a;
        bArr2[0] = 0;
        bArr2[1] = 0;
        bArr2[2] = 0;
        int i8 = 4 - this.f4271d;
        int i9 = 0;
        while (c2360t.m2569a() > 0) {
            c2360t.m2572d(this.f4270c.f6133a, i8, this.f4271d);
            this.f4270c.m2567C(0);
            int m2588t = this.f4270c.m2588t();
            this.f4269b.m2567C(0);
            this.f4268a.mo1613b(this.f4269b, 4);
            this.f4268a.mo1613b(c2360t, m2588t);
            i9 = i9 + 4 + m2588t;
        }
        this.f4268a.mo1614c(j3, i7, i9, 0, null);
        this.f4273f = true;
        return true;
    }
}
