package p476m.p477a.p485b.p493l0;

import java.io.Serializable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4906z;

/* renamed from: m.a.b.l0.k */
/* loaded from: classes3.dex */
public class C4863k implements InterfaceC4906z, Cloneable, Serializable {
    private static final long serialVersionUID = -6437800749411518984L;

    /* renamed from: c */
    public final String f12456c;

    /* renamed from: e */
    public final String f12457e;

    public C4863k(String str, String str2) {
        C2354n.m2470e1(str, "Name");
        this.f12456c = str;
        this.f12457e = str2;
    }

    public Object clone() {
        return super.clone();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof InterfaceC4906z)) {
            return false;
        }
        C4863k c4863k = (C4863k) obj;
        return this.f12456c.equals(c4863k.f12456c) && C2354n.m2446Y(this.f12457e, c4863k.f12457e);
    }

    @Override // p476m.p477a.p485b.InterfaceC4906z
    public String getName() {
        return this.f12456c;
    }

    @Override // p476m.p477a.p485b.InterfaceC4906z
    public String getValue() {
        return this.f12457e;
    }

    public int hashCode() {
        return C2354n.m2519u0(C2354n.m2519u0(17, this.f12456c), this.f12457e);
    }

    public String toString() {
        if (this.f12457e == null) {
            return this.f12456c;
        }
        StringBuilder sb = new StringBuilder(this.f12457e.length() + this.f12456c.length() + 1);
        sb.append(this.f12456c);
        sb.append("=");
        sb.append(this.f12457e);
        return sb.toString();
    }
}
