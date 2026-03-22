package p476m.p477a.p485b.p493l0;

import java.io.Serializable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4802g;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.l0.b */
/* loaded from: classes3.dex */
public class C4854b implements InterfaceC4800f, Cloneable, Serializable {

    /* renamed from: c */
    public static final InterfaceC4802g[] f12428c = new InterfaceC4802g[0];
    private static final long serialVersionUID = -5427236326487562174L;

    /* renamed from: e */
    public final String f12429e;

    /* renamed from: f */
    public final String f12430f;

    public C4854b(String str, String str2) {
        C2354n.m2470e1(str, "Name");
        this.f12429e = str;
        this.f12430f = str2;
    }

    public Object clone() {
        return super.clone();
    }

    @Override // p476m.p477a.p485b.InterfaceC4800f
    public InterfaceC4802g[] getElements() {
        String str = this.f12430f;
        if (str == null) {
            return f12428c;
        }
        C4856d c4856d = C4856d.f12434a;
        C2354n.m2470e1(str, "Value");
        C4893b c4893b = new C4893b(str.length());
        c4893b.m5559b(str);
        return C4856d.f12434a.m5522a(c4893b, new C4871s(0, str.length()));
    }

    @Override // p476m.p477a.p485b.InterfaceC4906z
    public String getName() {
        return this.f12429e;
    }

    @Override // p476m.p477a.p485b.InterfaceC4906z
    public String getValue() {
        return this.f12430f;
    }

    public String toString() {
        return C4860h.f12449a.m5532c(null, this).toString();
    }
}
