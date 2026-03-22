package p005b.p375z.p376a.p377a;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.z.a.a.b */
/* loaded from: classes2.dex */
public final class C2950b<A, B> {

    /* renamed from: a */
    public final A f8084a;

    /* renamed from: b */
    public final B f8085b;

    public C2950b(A a, B b2) {
        this.f8084a = a;
        this.f8085b = b2;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2950b.class != obj.getClass()) {
            return false;
        }
        C2950b c2950b = (C2950b) obj;
        A a = this.f8084a;
        if (a == null) {
            if (c2950b.f8084a != null) {
                return false;
            }
        } else if (!a.equals(c2950b.f8084a)) {
            return false;
        }
        B b2 = this.f8085b;
        if (b2 == null) {
            if (c2950b.f8085b != null) {
                return false;
            }
        } else if (!b2.equals(c2950b.f8085b)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        A a = this.f8084a;
        int hashCode = ((a == null ? 0 : a.hashCode()) + 31) * 31;
        B b2 = this.f8085b;
        return hashCode + (b2 != null ? b2.hashCode() : 0);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("first = ");
        m586H.append(this.f8084a);
        m586H.append(" , second = ");
        m586H.append(this.f8085b);
        return m586H.toString();
    }
}
