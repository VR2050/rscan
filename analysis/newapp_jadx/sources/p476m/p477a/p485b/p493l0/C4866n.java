package p476m.p477a.p485b.p493l0;

import java.util.Iterator;
import java.util.NoSuchElementException;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4791a0;
import p476m.p477a.p485b.InterfaceC4804h;

/* renamed from: m.a.b.l0.n */
/* loaded from: classes3.dex */
public class C4866n implements Iterator {

    /* renamed from: c */
    public final InterfaceC4804h f12464c;

    /* renamed from: e */
    public String f12465e;

    /* renamed from: f */
    public String f12466f;

    /* renamed from: g */
    public int f12467g;

    public C4866n(InterfaceC4804h interfaceC4804h) {
        C2354n.m2470e1(interfaceC4804h, "Header iterator");
        this.f12464c = interfaceC4804h;
        this.f12467g = m5538a(-1);
    }

    /* renamed from: a */
    public int m5538a(int i2) {
        String str;
        if (i2 >= 0) {
            C2354n.m2462c1(i2, "Search position");
            int length = this.f12465e.length();
            boolean z = false;
            while (!z && i2 < length) {
                char charAt = this.f12465e.charAt(i2);
                if (charAt == ',') {
                    z = true;
                } else {
                    if (!(charAt == '\t' || Character.isSpaceChar(charAt))) {
                        if (m5539c(charAt)) {
                            StringBuilder m588J = C1499a.m588J("Tokens without separator (pos ", i2, "): ");
                            m588J.append(this.f12465e);
                            throw new C4791a0(m588J.toString());
                        }
                        StringBuilder m588J2 = C1499a.m588J("Invalid character after token (pos ", i2, "): ");
                        m588J2.append(this.f12465e);
                        throw new C4791a0(m588J2.toString());
                    }
                    i2++;
                }
            }
        } else {
            if (!this.f12464c.hasNext()) {
                return -1;
            }
            this.f12465e = this.f12464c.mo5478b().getValue();
            i2 = 0;
        }
        C2354n.m2462c1(i2, "Search position");
        boolean z2 = false;
        while (!z2 && (str = this.f12465e) != null) {
            int length2 = str.length();
            while (!z2 && i2 < length2) {
                char charAt2 = this.f12465e.charAt(i2);
                if (!(charAt2 == ',')) {
                    if (!(charAt2 == '\t' || Character.isSpaceChar(charAt2))) {
                        if (!m5539c(this.f12465e.charAt(i2))) {
                            StringBuilder m588J3 = C1499a.m588J("Invalid character before token (pos ", i2, "): ");
                            m588J3.append(this.f12465e);
                            throw new C4791a0(m588J3.toString());
                        }
                        z2 = true;
                    }
                }
                i2++;
            }
            if (!z2) {
                if (this.f12464c.hasNext()) {
                    this.f12465e = this.f12464c.mo5478b().getValue();
                    i2 = 0;
                } else {
                    this.f12465e = null;
                }
            }
        }
        if (!z2) {
            i2 = -1;
        }
        if (i2 < 0) {
            this.f12466f = null;
            return -1;
        }
        C2354n.m2462c1(i2, "Search position");
        int length3 = this.f12465e.length();
        int i3 = i2;
        do {
            i3++;
            if (i3 >= length3) {
                break;
            }
        } while (m5539c(this.f12465e.charAt(i3)));
        this.f12466f = this.f12465e.substring(i2, i3);
        return i3;
    }

    /* renamed from: c */
    public boolean m5539c(char c2) {
        if (Character.isLetterOrDigit(c2)) {
            return true;
        }
        if (Character.isISOControl(c2)) {
            return false;
        }
        return !(" ,;=()<>@:\\\"/[]?{}\t".indexOf(c2) >= 0);
    }

    /* renamed from: d */
    public String m5540d() {
        String str = this.f12466f;
        if (str == null) {
            throw new NoSuchElementException("Iteration already finished.");
        }
        this.f12467g = m5538a(this.f12467g);
        return str;
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        return this.f12466f != null;
    }

    @Override // java.util.Iterator
    public final Object next() {
        return m5540d();
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Removing tokens is not supported.");
    }
}
