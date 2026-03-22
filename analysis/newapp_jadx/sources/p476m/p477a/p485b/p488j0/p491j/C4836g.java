package p476m.p477a.p485b.p488j0.p491j;

import java.net.Socket;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4790a;
import p476m.p477a.p485b.C4791a0;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.C4905y;
import p476m.p477a.p485b.InterfaceC4895o;
import p476m.p477a.p485b.InterfaceC4896p;
import p476m.p477a.p485b.p486h0.C4805a;
import p476m.p477a.p485b.p488j0.C4816d;
import p476m.p477a.p485b.p492k0.InterfaceC4850d;
import p476m.p477a.p485b.p493l0.C4857e;
import p476m.p477a.p485b.p493l0.C4858f;
import p476m.p477a.p485b.p493l0.C4861i;
import p476m.p477a.p485b.p493l0.C4864l;
import p476m.p477a.p485b.p493l0.C4871s;
import p476m.p477a.p485b.p493l0.InterfaceC4870r;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.j0.j.g */
/* loaded from: classes3.dex */
public class C4836g extends AbstractC4830a<InterfaceC4895o> {

    /* renamed from: g */
    public final InterfaceC4896p f12398g;

    /* renamed from: h */
    public final C4893b f12399h;

    public C4836g(InterfaceC4850d interfaceC4850d, InterfaceC4870r interfaceC4870r, InterfaceC4896p interfaceC4896p, C4805a c4805a) {
        super(interfaceC4850d, interfaceC4870r, c4805a);
        this.f12398g = interfaceC4896p == null ? C4816d.f12313a : interfaceC4896p;
        this.f12399h = new C4893b(128);
    }

    @Override // p476m.p477a.p485b.p488j0.p491j.AbstractC4830a
    /* renamed from: a */
    public InterfaceC4895o mo5492a(Socket socket, InterfaceC4850d interfaceC4850d) {
        C4893b c4893b = this.f12399h;
        c4893b.f12498e = 0;
        if (interfaceC4850d.mo5498a(c4893b) == -1) {
            throw new C4790a("Client closed connection");
        }
        int i2 = this.f12399h.f12498e;
        C4871s c4871s = new C4871s(0, i2);
        InterfaceC4870r interfaceC4870r = this.f12370d;
        C4893b c4893b2 = this.f12399h;
        C4861i c4861i = (C4861i) interfaceC4870r;
        Objects.requireNonNull(c4861i);
        C2354n.m2470e1(c4893b2, "Char array buffer");
        C2354n.m2470e1(c4871s, "Parser cursor");
        int i3 = c4871s.f12474b;
        try {
            c4861i.m5536b(c4893b2, c4871s);
            int i4 = c4871s.f12474b;
            int m5563f = c4893b2.m5563f(32, i4, i2);
            if (m5563f < 0) {
                throw new C4791a0("Invalid request line: " + c4893b2.m5564g(i3, i2));
            }
            String m5565h = c4893b2.m5565h(i4, m5563f);
            c4871s.m5542b(m5563f);
            c4861i.m5536b(c4893b2, c4871s);
            int i5 = c4871s.f12474b;
            int m5563f2 = c4893b2.m5563f(32, i5, i2);
            if (m5563f2 < 0) {
                throw new C4791a0("Invalid request line: " + c4893b2.m5564g(i3, i2));
            }
            String m5565h2 = c4893b2.m5565h(i5, m5563f2);
            c4871s.m5542b(m5563f2);
            C4795c0 m5535a = c4861i.m5535a(c4893b2, c4871s);
            c4861i.m5536b(c4893b2, c4871s);
            if (!c4871s.m5541a()) {
                throw new C4791a0("Invalid request line: " + c4893b2.m5564g(i3, i2));
            }
            C4864l c4864l = new C4864l(m5565h, m5565h2, m5535a);
            Objects.requireNonNull((C4816d) this.f12398g);
            C2354n.m2470e1(c4864l, "Request line");
            String mo5474d = c4864l.mo5474d();
            if (C4816d.m5485a(C4816d.f12314b, mo5474d)) {
                return new C4858f(socket, c4864l);
            }
            if (C4816d.m5485a(C4816d.f12315c, mo5474d)) {
                return new C4857e(socket, c4864l);
            }
            throw new C4905y(C1499a.m637w(mo5474d, " method not supported"));
        } catch (IndexOutOfBoundsException unused) {
            StringBuilder m586H = C1499a.m586H("Invalid request line: ");
            m586H.append(c4893b2.m5564g(i3, i2));
            throw new C4791a0(m586H.toString());
        }
    }
}
