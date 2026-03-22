package p476m.p477a.p485b.p488j0.p490i;

import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4793b0;
import p476m.p477a.p485b.C4902v;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4891n;
import p476m.p477a.p485b.p487i0.InterfaceC4811d;

/* renamed from: m.a.b.j0.i.c */
/* loaded from: classes3.dex */
public class C4829c implements InterfaceC4811d {

    /* renamed from: a */
    public static final C4829c f12366a = new C4829c();

    @Override // p476m.p477a.p485b.p487i0.InterfaceC4811d
    /* renamed from: a */
    public long mo5479a(InterfaceC4891n interfaceC4891n) {
        C2354n.m2470e1(interfaceC4891n, "HTTP message");
        InterfaceC4800f mo5519n = interfaceC4891n.mo5519n("Transfer-Encoding");
        if (mo5519n != null) {
            String value = mo5519n.getValue();
            if (!"chunked".equalsIgnoreCase(value)) {
                if ("identity".equalsIgnoreCase(value)) {
                    return -1L;
                }
                throw new C4793b0(C1499a.m637w("Unsupported transfer encoding: ", value));
            }
            if (!interfaceC4891n.mo5524a().m5470c(C4902v.f12500h)) {
                return -2L;
            }
            StringBuilder m586H = C1499a.m586H("Chunked transfer encoding not allowed for ");
            m586H.append(interfaceC4891n.mo5524a());
            throw new C4793b0(m586H.toString());
        }
        InterfaceC4800f mo5519n2 = interfaceC4891n.mo5519n("Content-Length");
        if (mo5519n2 == null) {
            return -1;
        }
        String value2 = mo5519n2.getValue();
        try {
            long parseLong = Long.parseLong(value2);
            if (parseLong >= 0) {
                return parseLong;
            }
            throw new C4793b0("Negative content length: " + value2);
        } catch (NumberFormatException unused) {
            throw new C4793b0(C1499a.m637w("Invalid content length: ", value2));
        }
    }
}
