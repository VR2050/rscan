package p005b.p199l.p200a.p201a.p227k1;

import android.util.Pair;
import java.util.Objects;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.p227k1.C2200w;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2111g0;

/* renamed from: b.l.a.a.k1.m */
/* loaded from: classes.dex */
public abstract class AbstractC2157m extends AbstractC2404x0 {

    /* renamed from: b */
    public final int f4853b;

    /* renamed from: c */
    public final InterfaceC2111g0 f4854c;

    /* renamed from: d */
    public final boolean f4855d;

    public AbstractC2157m(boolean z, InterfaceC2111g0 interfaceC2111g0) {
        this.f4855d = z;
        this.f4854c = interfaceC2111g0;
        this.f4853b = ((InterfaceC2111g0.a) interfaceC2111g0).f4583a;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: a */
    public int mo1926a(boolean z) {
        if (this.f4853b == 0) {
            return -1;
        }
        int i2 = 0;
        if (this.f4855d) {
            z = false;
        }
        if (z && ((InterfaceC2111g0.a) this.f4854c).f4583a <= 0) {
            i2 = -1;
        }
        do {
            C2200w.b bVar = (C2200w.b) this;
            if (!bVar.f5243e.m2691q()) {
                return bVar.f5243e.mo1926a(z) + (i2 * bVar.f5245g);
            }
            i2 = m1931r(i2, z);
        } while (i2 != -1);
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: b */
    public final int mo1831b(Object obj) {
        if (!(obj instanceof Pair)) {
            return -1;
        }
        Pair pair = (Pair) obj;
        Object obj2 = pair.first;
        Object obj3 = pair.second;
        int intValue = !(obj2 instanceof Integer) ? -1 : ((Integer) obj2).intValue();
        if (intValue == -1) {
            return -1;
        }
        C2200w.b bVar = (C2200w.b) this;
        int mo1831b = bVar.f5243e.mo1831b(obj3);
        if (mo1831b == -1) {
            return -1;
        }
        return (intValue * bVar.f5244f) + mo1831b;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: c */
    public int mo1927c(boolean z) {
        int i2;
        int i3 = this.f4853b;
        if (i3 == 0) {
            return -1;
        }
        if (this.f4855d) {
            z = false;
        }
        if (z) {
            int i4 = ((InterfaceC2111g0.a) this.f4854c).f4583a;
            i2 = i4 > 0 ? i4 - 1 : -1;
        } else {
            i2 = i3 - 1;
        }
        do {
            C2200w.b bVar = (C2200w.b) this;
            if (!bVar.f5243e.m2691q()) {
                return bVar.f5243e.mo1927c(z) + (i2 * bVar.f5245g);
            }
            i2 = m1932s(i2, z);
        } while (i2 != -1);
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: e */
    public int mo1928e(int i2, int i3, boolean z) {
        if (this.f4855d) {
            if (i3 == 1) {
                i3 = 2;
            }
            z = false;
        }
        C2200w.b bVar = (C2200w.b) this;
        int i4 = bVar.f5245g;
        int i5 = i2 / i4;
        int i6 = i4 * i5;
        int mo1928e = bVar.f5243e.mo1928e(i2 - i6, i3 != 2 ? i3 : 0, z);
        if (mo1928e != -1) {
            return i6 + mo1928e;
        }
        int m1931r = m1931r(i5, z);
        while (m1931r != -1 && bVar.f5243e.m2691q()) {
            m1931r = m1931r(m1931r, z);
        }
        if (m1931r != -1) {
            return bVar.f5243e.mo1926a(z) + (m1931r * bVar.f5245g);
        }
        if (i3 == 2) {
            return mo1926a(z);
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: g */
    public final AbstractC2404x0.b mo1832g(int i2, AbstractC2404x0.b bVar, boolean z) {
        C2200w.b bVar2 = (C2200w.b) this;
        int i3 = bVar2.f5244f;
        int i4 = i2 / i3;
        int i5 = bVar2.f5245g * i4;
        bVar2.f5243e.mo1832g(i2 - (i3 * i4), bVar, z);
        bVar.f6368b += i5;
        if (z) {
            Integer valueOf = Integer.valueOf(i4);
            Object obj = bVar.f6367a;
            Objects.requireNonNull(obj);
            bVar.f6367a = Pair.create(valueOf, obj);
        }
        return bVar;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: h */
    public final AbstractC2404x0.b mo1929h(Object obj, AbstractC2404x0.b bVar) {
        Pair pair = (Pair) obj;
        Object obj2 = pair.first;
        Object obj3 = pair.second;
        C2200w.b bVar2 = (C2200w.b) this;
        int intValue = (!(obj2 instanceof Integer) ? -1 : ((Integer) obj2).intValue()) * bVar2.f5245g;
        bVar2.f5243e.mo1929h(obj3, bVar);
        bVar.f6368b += intValue;
        bVar.f6367a = obj;
        return bVar;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: l */
    public int mo1930l(int i2, int i3, boolean z) {
        if (this.f4855d) {
            if (i3 == 1) {
                i3 = 2;
            }
            z = false;
        }
        C2200w.b bVar = (C2200w.b) this;
        int i4 = bVar.f5245g;
        int i5 = i2 / i4;
        int i6 = i4 * i5;
        int mo1930l = bVar.f5243e.mo1930l(i2 - i6, i3 != 2 ? i3 : 0, z);
        if (mo1930l != -1) {
            return i6 + mo1930l;
        }
        int m1932s = m1932s(i5, z);
        while (m1932s != -1 && bVar.f5243e.m2691q()) {
            m1932s = m1932s(m1932s, z);
        }
        if (m1932s != -1) {
            return bVar.f5243e.mo1927c(z) + (m1932s * bVar.f5245g);
        }
        if (i3 == 2) {
            return mo1927c(z);
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: m */
    public final Object mo1834m(int i2) {
        C2200w.b bVar = (C2200w.b) this;
        int i3 = bVar.f5244f;
        int i4 = i2 / i3;
        return Pair.create(Integer.valueOf(i4), bVar.f5243e.mo1834m(i2 - (i3 * i4)));
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
    /* renamed from: o */
    public final AbstractC2404x0.c mo1835o(int i2, AbstractC2404x0.c cVar, long j2) {
        C2200w.b bVar = (C2200w.b) this;
        int i3 = bVar.f5245g;
        int i4 = i2 / i3;
        int i5 = bVar.f5244f * i4;
        bVar.f5243e.mo1835o(i2 - (i3 * i4), cVar, j2);
        Object valueOf = Integer.valueOf(i4);
        if (!AbstractC2404x0.c.f6372a.equals(cVar.f6373b)) {
            valueOf = Pair.create(valueOf, cVar.f6373b);
        }
        cVar.f6373b = valueOf;
        cVar.f6378g += i5;
        cVar.f6379h += i5;
        return cVar;
    }

    /* renamed from: r */
    public final int m1931r(int i2, boolean z) {
        if (!z) {
            if (i2 < this.f4853b - 1) {
                return i2 + 1;
            }
            return -1;
        }
        int i3 = i2 + 1;
        if (i3 < ((InterfaceC2111g0.a) this.f4854c).f4583a) {
            return i3;
        }
        return -1;
    }

    /* renamed from: s */
    public final int m1932s(int i2, boolean z) {
        if (!z) {
            if (i2 > 0) {
                return i2 - 1;
            }
            return -1;
        }
        Objects.requireNonNull((InterfaceC2111g0.a) this.f4854c);
        int i3 = i2 - 1;
        if (i3 >= 0) {
            return i3;
        }
        return -1;
    }
}
