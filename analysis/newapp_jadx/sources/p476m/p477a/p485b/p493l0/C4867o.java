package p476m.p477a.p485b.p493l0;

import java.io.Serializable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4791a0;
import p476m.p477a.p485b.InterfaceC4798e;
import p476m.p477a.p485b.InterfaceC4802g;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.l0.o */
/* loaded from: classes3.dex */
public class C4867o implements InterfaceC4798e, Cloneable, Serializable {
    private static final long serialVersionUID = -2768352615787625448L;

    /* renamed from: c */
    public final String f12468c;

    /* renamed from: e */
    public final C4893b f12469e;

    /* renamed from: f */
    public final int f12470f;

    public C4867o(C4893b c4893b) {
        C2354n.m2470e1(c4893b, "Char array buffer");
        int m5563f = c4893b.m5563f(58, 0, c4893b.f12498e);
        if (m5563f == -1) {
            StringBuilder m586H = C1499a.m586H("Invalid header: ");
            m586H.append(c4893b.toString());
            throw new C4791a0(m586H.toString());
        }
        String m5565h = c4893b.m5565h(0, m5563f);
        if (m5565h.isEmpty()) {
            StringBuilder m586H2 = C1499a.m586H("Invalid header: ");
            m586H2.append(c4893b.toString());
            throw new C4791a0(m586H2.toString());
        }
        this.f12469e = c4893b;
        this.f12468c = m5565h;
        this.f12470f = m5563f + 1;
    }

    public Object clone() {
        return super.clone();
    }

    @Override // p476m.p477a.p485b.InterfaceC4798e
    public C4893b getBuffer() {
        return this.f12469e;
    }

    @Override // p476m.p477a.p485b.InterfaceC4800f
    public InterfaceC4802g[] getElements() {
        C4871s c4871s = new C4871s(0, this.f12469e.f12498e);
        c4871s.m5542b(this.f12470f);
        return C4856d.f12434a.m5522a(this.f12469e, c4871s);
    }

    @Override // p476m.p477a.p485b.InterfaceC4906z
    public String getName() {
        return this.f12468c;
    }

    @Override // p476m.p477a.p485b.InterfaceC4906z
    public String getValue() {
        C4893b c4893b = this.f12469e;
        return c4893b.m5565h(this.f12470f, c4893b.f12498e);
    }

    public String toString() {
        return this.f12469e.toString();
    }
}
