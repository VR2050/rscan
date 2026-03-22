package p005b.p199l.p200a.p201a.p208f1.p214f0;

import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.r */
/* loaded from: classes.dex */
public final class C2027r implements InterfaceC2011c0 {

    /* renamed from: a */
    public final InterfaceC2019j f4071a;

    /* renamed from: b */
    public final C2359s f4072b = new C2359s(new byte[10]);

    /* renamed from: c */
    public int f4073c = 0;

    /* renamed from: d */
    public int f4074d;

    /* renamed from: e */
    public C2342c0 f4075e;

    /* renamed from: f */
    public boolean f4076f;

    /* renamed from: g */
    public boolean f4077g;

    /* renamed from: h */
    public boolean f4078h;

    /* renamed from: i */
    public int f4079i;

    /* renamed from: j */
    public int f4080j;

    /* renamed from: k */
    public boolean f4081k;

    /* renamed from: l */
    public long f4082l;

    public C2027r(InterfaceC2019j interfaceC2019j) {
        this.f4071a = interfaceC2019j;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0
    /* renamed from: a */
    public void mo1580a(C2342c0 c2342c0, InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        this.f4075e = c2342c0;
        this.f4071a.mo1576e(interfaceC2042i, dVar);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0
    /* renamed from: b */
    public final void mo1581b(C2360t c2360t, int i2) {
        boolean z;
        if ((i2 & 1) != 0) {
            int i3 = this.f4073c;
            if (i3 != 0 && i3 != 1 && i3 != 2) {
                if (i3 != 3) {
                    throw new IllegalStateException();
                }
                int i4 = this.f4080j;
                this.f4071a.mo1575d();
            }
            m1606e(1);
        }
        int i5 = i2;
        while (c2360t.m2569a() > 0) {
            int i6 = this.f4073c;
            if (i6 != 0) {
                if (i6 != 1) {
                    if (i6 == 2) {
                        if (m1605d(c2360t, this.f4072b.f6129a, Math.min(10, this.f4079i)) && m1605d(c2360t, null, this.f4079i)) {
                            this.f4072b.m2562j(0);
                            this.f4082l = -9223372036854775807L;
                            if (this.f4076f) {
                                this.f4072b.m2564l(4);
                                this.f4072b.m2564l(1);
                                this.f4072b.m2564l(1);
                                long m2558f = (this.f4072b.m2558f(3) << 30) | (this.f4072b.m2558f(15) << 15) | this.f4072b.m2558f(15);
                                this.f4072b.m2564l(1);
                                if (!this.f4078h && this.f4077g) {
                                    this.f4072b.m2564l(4);
                                    this.f4072b.m2564l(1);
                                    this.f4072b.m2564l(1);
                                    this.f4072b.m2564l(1);
                                    this.f4075e.m2306b((this.f4072b.m2558f(3) << 30) | (this.f4072b.m2558f(15) << 15) | this.f4072b.m2558f(15));
                                    this.f4078h = true;
                                }
                                this.f4082l = this.f4075e.m2306b(m2558f);
                            }
                            i5 |= this.f4081k ? 4 : 0;
                            this.f4071a.mo1577f(this.f4082l, i5);
                            m1606e(3);
                        }
                    } else {
                        if (i6 != 3) {
                            throw new IllegalStateException();
                        }
                        int m2569a = c2360t.m2569a();
                        int i7 = this.f4080j;
                        int i8 = i7 != -1 ? m2569a - i7 : 0;
                        if (i8 > 0) {
                            m2569a -= i8;
                            c2360t.m2566B(c2360t.f6134b + m2569a);
                        }
                        this.f4071a.mo1573b(c2360t);
                        int i9 = this.f4080j;
                        if (i9 != -1) {
                            int i10 = i9 - m2569a;
                            this.f4080j = i10;
                            if (i10 == 0) {
                                this.f4071a.mo1575d();
                                m1606e(1);
                            }
                        }
                    }
                } else if (m1605d(c2360t, this.f4072b.f6129a, 9)) {
                    this.f4072b.m2562j(0);
                    if (this.f4072b.m2558f(24) != 1) {
                        this.f4080j = -1;
                        z = false;
                    } else {
                        this.f4072b.m2564l(8);
                        int m2558f2 = this.f4072b.m2558f(16);
                        this.f4072b.m2564l(5);
                        this.f4081k = this.f4072b.m2557e();
                        this.f4072b.m2564l(2);
                        this.f4076f = this.f4072b.m2557e();
                        this.f4077g = this.f4072b.m2557e();
                        this.f4072b.m2564l(6);
                        int m2558f3 = this.f4072b.m2558f(8);
                        this.f4079i = m2558f3;
                        if (m2558f2 == 0) {
                            this.f4080j = -1;
                        } else {
                            this.f4080j = ((m2558f2 + 6) - 9) - m2558f3;
                        }
                        z = true;
                    }
                    m1606e(z ? 2 : 0);
                }
            } else {
                c2360t.m2568D(c2360t.m2569a());
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0
    /* renamed from: c */
    public final void mo1582c() {
        this.f4073c = 0;
        this.f4074d = 0;
        this.f4078h = false;
        this.f4071a.mo1574c();
    }

    /* renamed from: d */
    public final boolean m1605d(C2360t c2360t, byte[] bArr, int i2) {
        int min = Math.min(c2360t.m2569a(), i2 - this.f4074d);
        if (min <= 0) {
            return true;
        }
        if (bArr == null) {
            c2360t.m2568D(min);
        } else {
            System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, this.f4074d, min);
            c2360t.f6134b += min;
        }
        int i3 = this.f4074d + min;
        this.f4074d = i3;
        return i3 == i2;
    }

    /* renamed from: e */
    public final void m1606e(int i2) {
        this.f4073c = i2;
        this.f4074d = 0;
    }
}
