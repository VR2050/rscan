package p005b.p199l.p200a.p201a.p227k1;

/* renamed from: b.l.a.a.k1.r */
/* loaded from: classes.dex */
public class C2195r implements InterfaceC2109f0 {

    /* renamed from: c */
    public final InterfaceC2109f0[] f5232c;

    public C2195r(InterfaceC2109f0[] interfaceC2109f0Arr) {
        this.f5232c = interfaceC2109f0Arr;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public final long mo1759b() {
        long j2 = Long.MAX_VALUE;
        for (InterfaceC2109f0 interfaceC2109f0 : this.f5232c) {
            long mo1759b = interfaceC2109f0.mo1759b();
            if (mo1759b != Long.MIN_VALUE) {
                j2 = Math.min(j2, mo1759b);
            }
        }
        if (j2 == Long.MAX_VALUE) {
            return Long.MIN_VALUE;
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        boolean z;
        boolean z2 = false;
        do {
            long mo1759b = mo1759b();
            if (mo1759b == Long.MIN_VALUE) {
                break;
            }
            z = false;
            for (InterfaceC2109f0 interfaceC2109f0 : this.f5232c) {
                long mo1759b2 = interfaceC2109f0.mo1759b();
                boolean z3 = mo1759b2 != Long.MIN_VALUE && mo1759b2 <= j2;
                if (mo1759b2 == mo1759b || z3) {
                    z |= interfaceC2109f0.mo1760c(j2);
                }
            }
            z2 |= z;
        } while (z);
        return z2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        for (InterfaceC2109f0 interfaceC2109f0 : this.f5232c) {
            if (interfaceC2109f0.mo1761d()) {
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public final long mo1763f() {
        long j2 = Long.MAX_VALUE;
        for (InterfaceC2109f0 interfaceC2109f0 : this.f5232c) {
            long mo1763f = interfaceC2109f0.mo1763f();
            if (mo1763f != Long.MIN_VALUE) {
                j2 = Math.min(j2, mo1763f);
            }
        }
        if (j2 == Long.MAX_VALUE) {
            return Long.MIN_VALUE;
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public final void mo1764g(long j2) {
        for (InterfaceC2109f0 interfaceC2109f0 : this.f5232c) {
            interfaceC2109f0.mo1764g(j2);
        }
    }
}
