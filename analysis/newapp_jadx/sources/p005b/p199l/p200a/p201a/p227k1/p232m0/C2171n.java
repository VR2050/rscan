package p005b.p199l.p200a.p201a.p227k1.p232m0;

import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2172o;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.m0.n */
/* loaded from: classes.dex */
public final class C2171n implements InterfaceC2107e0 {

    /* renamed from: c */
    public final int f4940c;

    /* renamed from: e */
    public final C2172o f4941e;

    /* renamed from: f */
    public int f4942f = -1;

    public C2171n(C2172o c2172o, int i2) {
        this.f4941e = c2172o;
        this.f4940c = i2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: a */
    public void mo1786a() {
        int i2 = this.f4942f;
        if (i2 == -2) {
            C2172o c2172o = this.f4941e;
            c2172o.m1964v();
            TrackGroupArray trackGroupArray = c2172o.f4953J;
            throw new C2173p(trackGroupArray.f9398f[this.f4940c].f9394e[0].f9245l);
        }
        if (i2 == -1) {
            this.f4941e.m1959C();
        } else if (i2 != -3) {
            C2172o c2172o2 = this.f4941e;
            c2172o2.m1959C();
            c2172o2.f4987w[i2].m1827w();
        }
    }

    /* renamed from: b */
    public void m1953b() {
        C4195m.m4765F(this.f4942f == -1);
        C2172o c2172o = this.f4941e;
        int i2 = this.f4940c;
        c2172o.m1964v();
        Objects.requireNonNull(c2172o.f4955L);
        int i3 = c2172o.f4955L[i2];
        if (i3 == -1) {
            if (c2172o.f4954K.contains(c2172o.f4953J.f9398f[i2])) {
                i3 = -3;
            }
            i3 = -2;
        } else {
            boolean[] zArr = c2172o.f4958O;
            if (!zArr[i3]) {
                zArr[i3] = true;
            }
            i3 = -2;
        }
        this.f4942f = i3;
    }

    /* renamed from: c */
    public final boolean m1954c() {
        int i2 = this.f4942f;
        return (i2 == -1 || i2 == -3 || i2 == -2) ? false : true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: i */
    public int mo1787i(C1964f0 c1964f0, C1945e c1945e, boolean z) {
        Format format;
        if (this.f4942f == -3) {
            c1945e.addFlag(4);
            return -4;
        }
        if (!m1954c()) {
            return -3;
        }
        C2172o c2172o = this.f4941e;
        int i2 = this.f4942f;
        if (c2172o.m1957A()) {
            return -3;
        }
        int i3 = 0;
        if (!c2172o.f4980p.isEmpty()) {
            int i4 = 0;
            while (true) {
                boolean z2 = true;
                if (i4 >= c2172o.f4980p.size() - 1) {
                    break;
                }
                int i5 = c2172o.f4980p.get(i4).f4904l;
                int length = c2172o.f4987w.length;
                int i6 = 0;
                while (true) {
                    if (i6 < length) {
                        if (c2172o.f4958O[i6] && c2172o.f4987w[i6].m1829y() == i5) {
                            z2 = false;
                            break;
                        }
                        i6++;
                    } else {
                        break;
                    }
                }
                if (!z2) {
                    break;
                }
                i4++;
            }
            C2344d0.m2312D(c2172o.f4980p, 0, i4);
            C2169l c2169l = c2172o.f4980p.get(0);
            Format format2 = c2169l.f4625c;
            if (!format2.equals(c2172o.f4951H)) {
                c2172o.f4977m.m2026b(c2172o.f4969e, format2, c2169l.f4626d, c2169l.f4627e, c2169l.f4628f);
            }
            c2172o.f4951H = format2;
        }
        int m1803A = c2172o.f4987w[i2].m1803A(c1964f0, c1945e, z, c2172o.f4964U, c2172o.f4960Q);
        if (m1803A == -5) {
            Format format3 = c1964f0.f3394c;
            Objects.requireNonNull(format3);
            if (i2 == c2172o.f4946C) {
                int m1829y = c2172o.f4987w[i2].m1829y();
                while (i3 < c2172o.f4980p.size() && c2172o.f4980p.get(i3).f4904l != m1829y) {
                    i3++;
                }
                if (i3 < c2172o.f4980p.size()) {
                    format = c2172o.f4980p.get(i3).f4625c;
                } else {
                    format = c2172o.f4950G;
                    Objects.requireNonNull(format);
                }
                format3 = format3.m4046q(format);
            }
            c1964f0.f3394c = format3;
        }
        return m1803A;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    public boolean isReady() {
        if (this.f4942f != -3) {
            if (!m1954c()) {
                return false;
            }
            C2172o c2172o = this.f4941e;
            if (!(!c2172o.m1957A() && c2172o.f4987w[this.f4942f].m1825u(c2172o.f4964U))) {
                return false;
            }
        }
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: o */
    public int mo1788o(long j2) {
        if (!m1954c()) {
            return 0;
        }
        C2172o c2172o = this.f4941e;
        int i2 = this.f4942f;
        if (c2172o.m1957A()) {
            return 0;
        }
        C2172o.c cVar = c2172o.f4987w[i2];
        return (!c2172o.f4964U || j2 <= cVar.m1818n()) ? cVar.m1809e(j2) : cVar.m1810f();
    }
}
