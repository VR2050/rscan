package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.p202a1.C1916h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.d */
/* loaded from: classes.dex */
public final class C2012d implements InterfaceC2019j {

    /* renamed from: a */
    public final C2359s f3864a;

    /* renamed from: b */
    public final C2360t f3865b;

    /* renamed from: c */
    public final String f3866c;

    /* renamed from: d */
    public String f3867d;

    /* renamed from: e */
    public InterfaceC2052s f3868e;

    /* renamed from: f */
    public int f3869f;

    /* renamed from: g */
    public int f3870g;

    /* renamed from: h */
    public boolean f3871h;

    /* renamed from: i */
    public boolean f3872i;

    /* renamed from: j */
    public long f3873j;

    /* renamed from: k */
    public Format f3874k;

    /* renamed from: l */
    public int f3875l;

    /* renamed from: m */
    public long f3876m;

    public C2012d(String str) {
        C2359s c2359s = new C2359s(new byte[16]);
        this.f3864a = c2359s;
        this.f3865b = new C2360t(c2359s.f6129a);
        this.f3869f = 0;
        this.f3870g = 0;
        this.f3871h = false;
        this.f3872i = false;
        this.f3866c = str;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: b */
    public void mo1573b(C2360t c2360t) {
        boolean z;
        int m2585q;
        while (c2360t.m2569a() > 0) {
            int i2 = this.f3869f;
            if (i2 == 0) {
                while (true) {
                    if (c2360t.m2569a() <= 0) {
                        z = false;
                        break;
                    } else if (this.f3871h) {
                        m2585q = c2360t.m2585q();
                        this.f3871h = m2585q == 172;
                        if (m2585q == 64 || m2585q == 65) {
                            break;
                        }
                    } else {
                        this.f3871h = c2360t.m2585q() == 172;
                    }
                }
                this.f3872i = m2585q == 65;
                z = true;
                if (z) {
                    this.f3869f = 1;
                    byte[] bArr = this.f3865b.f6133a;
                    bArr[0] = -84;
                    bArr[1] = (byte) (this.f3872i ? 65 : 64);
                    this.f3870g = 2;
                }
            } else if (i2 == 1) {
                byte[] bArr2 = this.f3865b.f6133a;
                int min = Math.min(c2360t.m2569a(), 16 - this.f3870g);
                System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr2, this.f3870g, min);
                c2360t.f6134b += min;
                int i3 = this.f3870g + min;
                this.f3870g = i3;
                if (i3 == 16) {
                    this.f3864a.m2562j(0);
                    C1916h.b m1265b = C1916h.m1265b(this.f3864a);
                    Format format = this.f3874k;
                    if (format == null || 2 != format.f9258y || m1265b.f3063a != format.f9259z || !"audio/ac4".equals(format.f9245l)) {
                        Format m4024A = Format.m4024A(this.f3867d, "audio/ac4", null, -1, -1, 2, m1265b.f3063a, null, null, 0, this.f3866c);
                        this.f3874k = m4024A;
                        this.f3868e.mo1615d(m4024A);
                    }
                    this.f3875l = m1265b.f3064b;
                    this.f3873j = (m1265b.f3065c * 1000000) / this.f3874k.f9259z;
                    this.f3865b.m2567C(0);
                    this.f3868e.mo1613b(this.f3865b, 16);
                    this.f3869f = 2;
                }
            } else if (i2 == 2) {
                int min2 = Math.min(c2360t.m2569a(), this.f3875l - this.f3870g);
                this.f3868e.mo1613b(c2360t, min2);
                int i4 = this.f3870g + min2;
                this.f3870g = i4;
                int i5 = this.f3875l;
                if (i4 == i5) {
                    this.f3868e.mo1614c(this.f3876m, 1, i5, 0, null);
                    this.f3876m += this.f3873j;
                    this.f3869f = 0;
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: c */
    public void mo1574c() {
        this.f3869f = 0;
        this.f3870g = 0;
        this.f3871h = false;
        this.f3872i = false;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: d */
    public void mo1575d() {
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: e */
    public void mo1576e(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        dVar.m1584a();
        this.f3867d = dVar.m1585b();
        this.f3868e = interfaceC2042i.mo1625t(dVar.m1586c(), 1);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: f */
    public void mo1577f(long j2, int i2) {
        this.f3876m = j2;
    }
}
