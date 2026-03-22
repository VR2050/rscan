package p476m.p477a.p485b.p488j0.p490i;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4791a0;
import p476m.p477a.p485b.C4793b0;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4802g;
import p476m.p477a.p485b.InterfaceC4891n;
import p476m.p477a.p485b.p487i0.InterfaceC4811d;

/* renamed from: m.a.b.j0.i.b */
/* loaded from: classes3.dex */
public class C4828b implements InterfaceC4811d {

    /* renamed from: a */
    public static final C4828b f12364a = new C4828b();

    /* renamed from: b */
    public final int f12365b;

    public C4828b() {
        this.f12365b = -1;
    }

    @Override // p476m.p477a.p485b.p487i0.InterfaceC4811d
    /* renamed from: a */
    public long mo5479a(InterfaceC4891n interfaceC4891n) {
        long j2;
        C2354n.m2470e1(interfaceC4891n, "HTTP message");
        InterfaceC4800f mo5519n = interfaceC4891n.mo5519n("Transfer-Encoding");
        if (mo5519n != null) {
            try {
                InterfaceC4802g[] elements = mo5519n.getElements();
                int length = elements.length;
                return (!"identity".equalsIgnoreCase(mo5519n.getValue()) && length > 0 && "chunked".equalsIgnoreCase(elements[length + (-1)].getName())) ? -2L : -1L;
            } catch (C4791a0 e2) {
                throw new C4793b0("Invalid Transfer-Encoding header value: " + mo5519n, e2);
            }
        }
        if (interfaceC4891n.mo5519n("Content-Length") == null) {
            return this.f12365b;
        }
        InterfaceC4800f[] mo5513c = interfaceC4891n.mo5513c("Content-Length");
        int length2 = mo5513c.length;
        while (true) {
            length2--;
            if (length2 < 0) {
                j2 = -1;
                break;
            }
            try {
                j2 = Long.parseLong(mo5513c[length2].getValue());
                break;
            } catch (NumberFormatException unused) {
            }
        }
        if (j2 >= 0) {
            return j2;
        }
        return -1L;
    }

    public C4828b(int i2) {
        this.f12365b = i2;
    }
}
