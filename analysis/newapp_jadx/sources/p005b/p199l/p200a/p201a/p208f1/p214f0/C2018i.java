package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.i */
/* loaded from: classes.dex */
public final class C2018i implements InterfaceC2019j {

    /* renamed from: a */
    public final List<InterfaceC2011c0.a> f3924a;

    /* renamed from: b */
    public final InterfaceC2052s[] f3925b;

    /* renamed from: c */
    public boolean f3926c;

    /* renamed from: d */
    public int f3927d;

    /* renamed from: e */
    public int f3928e;

    /* renamed from: f */
    public long f3929f;

    public C2018i(List<InterfaceC2011c0.a> list) {
        this.f3924a = list;
        this.f3925b = new InterfaceC2052s[list.size()];
    }

    /* renamed from: a */
    public final boolean m1594a(C2360t c2360t, int i2) {
        if (c2360t.m2569a() == 0) {
            return false;
        }
        if (c2360t.m2585q() != i2) {
            this.f3926c = false;
        }
        this.f3927d--;
        return this.f3926c;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: b */
    public void mo1573b(C2360t c2360t) {
        if (this.f3926c) {
            if (this.f3927d != 2 || m1594a(c2360t, 32)) {
                if (this.f3927d != 1 || m1594a(c2360t, 0)) {
                    int i2 = c2360t.f6134b;
                    int m2569a = c2360t.m2569a();
                    for (InterfaceC2052s interfaceC2052s : this.f3925b) {
                        c2360t.m2567C(i2);
                        interfaceC2052s.mo1613b(c2360t, m2569a);
                    }
                    this.f3928e += m2569a;
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: c */
    public void mo1574c() {
        this.f3926c = false;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: d */
    public void mo1575d() {
        if (this.f3926c) {
            for (InterfaceC2052s interfaceC2052s : this.f3925b) {
                interfaceC2052s.mo1614c(this.f3929f, 1, this.f3928e, 0, null);
            }
            this.f3926c = false;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: e */
    public void mo1576e(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        for (int i2 = 0; i2 < this.f3925b.length; i2++) {
            InterfaceC2011c0.a aVar = this.f3924a.get(i2);
            dVar.m1584a();
            InterfaceC2052s mo1625t = interfaceC2042i.mo1625t(dVar.m1586c(), 3);
            mo1625t.mo1615d(Format.m4026C(dVar.m1585b(), "application/dvbsubs", null, -1, 0, Collections.singletonList(aVar.f3854b), aVar.f3853a, null));
            this.f3925b[i2] = mo1625t;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: f */
    public void mo1577f(long j2, int i2) {
        if ((i2 & 4) == 0) {
            return;
        }
        this.f3926c = true;
        this.f3929f = j2;
        this.f3928e = 0;
        this.f3927d = 2;
    }
}
