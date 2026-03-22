package p476m.p477a.p485b.p493l0;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4802g;
import p476m.p477a.p485b.InterfaceC4906z;

/* renamed from: m.a.b.l0.c */
/* loaded from: classes3.dex */
public class C4855c implements InterfaceC4802g, Cloneable {

    /* renamed from: c */
    public final String f12431c;

    /* renamed from: e */
    public final String f12432e;

    /* renamed from: f */
    public final InterfaceC4906z[] f12433f;

    public C4855c(String str, String str2, InterfaceC4906z[] interfaceC4906zArr) {
        C2354n.m2470e1(str, "Name");
        this.f12431c = str;
        this.f12432e = str2;
        if (interfaceC4906zArr != null) {
            this.f12433f = interfaceC4906zArr;
        } else {
            this.f12433f = new InterfaceC4906z[0];
        }
    }

    public Object clone() {
        return super.clone();
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0025, code lost:
    
        if (r7 == null) goto L14;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean equals(java.lang.Object r7) {
        /*
            r6 = this;
            r0 = 1
            if (r6 != r7) goto L4
            return r0
        L4:
            boolean r1 = r7 instanceof p476m.p477a.p485b.InterfaceC4802g
            r2 = 0
            if (r1 == 0) goto L48
            m.a.b.l0.c r7 = (p476m.p477a.p485b.p493l0.C4855c) r7
            java.lang.String r1 = r6.f12431c
            java.lang.String r3 = r7.f12431c
            boolean r1 = r1.equals(r3)
            if (r1 == 0) goto L46
            java.lang.String r1 = r6.f12432e
            java.lang.String r3 = r7.f12432e
            boolean r1 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2446Y(r1, r3)
            if (r1 == 0) goto L46
            m.a.b.z[] r1 = r6.f12433f
            m.a.b.z[] r7 = r7.f12433f
            if (r1 != 0) goto L2b
            if (r7 != 0) goto L29
        L27:
            r7 = 1
            goto L43
        L29:
            r7 = 0
            goto L43
        L2b:
            if (r7 == 0) goto L29
            int r3 = r1.length
            int r4 = r7.length
            if (r3 != r4) goto L29
            r3 = 0
        L32:
            int r4 = r1.length
            if (r3 >= r4) goto L27
            r4 = r1[r3]
            r5 = r7[r3]
            boolean r4 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2446Y(r4, r5)
            if (r4 != 0) goto L40
            goto L29
        L40:
            int r3 = r3 + 1
            goto L32
        L43:
            if (r7 == 0) goto L46
            goto L47
        L46:
            r0 = 0
        L47:
            return r0
        L48:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p477a.p485b.p493l0.C4855c.equals(java.lang.Object):boolean");
    }

    @Override // p476m.p477a.p485b.InterfaceC4802g
    public String getName() {
        return this.f12431c;
    }

    public int hashCode() {
        int m2519u0 = C2354n.m2519u0(C2354n.m2519u0(17, this.f12431c), this.f12432e);
        for (InterfaceC4906z interfaceC4906z : this.f12433f) {
            m2519u0 = C2354n.m2519u0(m2519u0, interfaceC4906z);
        }
        return m2519u0;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.f12431c);
        if (this.f12432e != null) {
            sb.append("=");
            sb.append(this.f12432e);
        }
        for (InterfaceC4906z interfaceC4906z : this.f12433f) {
            sb.append("; ");
            sb.append(interfaceC4906z);
        }
        return sb.toString();
    }
}
