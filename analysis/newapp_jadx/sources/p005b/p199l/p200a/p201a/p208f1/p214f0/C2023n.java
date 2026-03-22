package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.n */
/* loaded from: classes.dex */
public final class C2023n implements InterfaceC2019j {

    /* renamed from: a */
    public final C2360t f4028a = new C2360t(10);

    /* renamed from: b */
    public InterfaceC2052s f4029b;

    /* renamed from: c */
    public boolean f4030c;

    /* renamed from: d */
    public long f4031d;

    /* renamed from: e */
    public int f4032e;

    /* renamed from: f */
    public int f4033f;

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: b */
    public void mo1573b(C2360t c2360t) {
        if (this.f4030c) {
            int m2569a = c2360t.m2569a();
            int i2 = this.f4033f;
            if (i2 < 10) {
                int min = Math.min(m2569a, 10 - i2);
                System.arraycopy(c2360t.f6133a, c2360t.f6134b, this.f4028a.f6133a, this.f4033f, min);
                if (this.f4033f + min == 10) {
                    this.f4028a.m2567C(0);
                    if (73 != this.f4028a.m2585q() || 68 != this.f4028a.m2585q() || 51 != this.f4028a.m2585q()) {
                        this.f4030c = false;
                        return;
                    } else {
                        this.f4028a.m2568D(3);
                        this.f4032e = this.f4028a.m2584p() + 10;
                    }
                }
            }
            int min2 = Math.min(m2569a, this.f4032e - this.f4033f);
            this.f4029b.mo1613b(c2360t, min2);
            this.f4033f += min2;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: c */
    public void mo1574c() {
        this.f4030c = false;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: d */
    public void mo1575d() {
        int i2;
        if (this.f4030c && (i2 = this.f4032e) != 0 && this.f4033f == i2) {
            this.f4029b.mo1614c(this.f4031d, 1, i2, 0, null);
            this.f4030c = false;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: e */
    public void mo1576e(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        dVar.m1584a();
        InterfaceC2052s mo1625t = interfaceC2042i.mo1625t(dVar.m1586c(), 4);
        this.f4029b = mo1625t;
        mo1625t.mo1615d(Format.m4028E(dVar.m1585b(), "application/id3", null, -1, null));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: f */
    public void mo1577f(long j2, int i2) {
        if ((i2 & 4) == 0) {
            return;
        }
        this.f4030c = true;
        this.f4031d = j2;
        this.f4032e = 0;
        this.f4033f = 0;
    }
}
