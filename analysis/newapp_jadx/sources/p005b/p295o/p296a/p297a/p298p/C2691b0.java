package p005b.p295o.p296a.p297a.p298p;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.o.a.a.p.b0 */
/* loaded from: classes2.dex */
public class C2691b0 extends Exception {

    /* renamed from: c */
    public Throwable f7361c;

    public C2691b0(C2689a0 c2689a0, String str) {
        super(c2689a0 + " " + str);
        this.f7361c = null;
    }

    /* renamed from: a */
    public static String m3232a(C2706q c2706q) {
        int i2 = c2706q.f7368a;
        if (i2 == -3) {
            return c2706q.f7370c;
        }
        if (i2 == -2) {
            return C1499a.m580B(new StringBuilder(), c2706q.f7369b, "");
        }
        if (i2 == -1) {
            return "<end of expression>";
        }
        return ((char) c2706q.f7368a) + "";
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.f7361c;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2691b0(p005b.p295o.p296a.p297a.p298p.C2689a0 r4, java.lang.String r5, p005b.p295o.p296a.p297a.p298p.C2706q r6, java.lang.String r7) {
        /*
            r3 = this;
            java.lang.String r0 = " got \""
            java.lang.StringBuilder r5 = p005b.p131d.p132a.p133a.C1499a.m590L(r5, r0)
            java.lang.StringBuffer r0 = new java.lang.StringBuffer     // Catch: java.io.IOException -> L29
            r0.<init>()     // Catch: java.io.IOException -> L29
            java.lang.String r1 = m3232a(r6)     // Catch: java.io.IOException -> L29
            r0.append(r1)     // Catch: java.io.IOException -> L29
            int r1 = r6.f7368a     // Catch: java.io.IOException -> L29
            r2 = -1
            if (r1 == r2) goto L24
            r6.m3235a()     // Catch: java.io.IOException -> L29
            java.lang.String r1 = m3232a(r6)     // Catch: java.io.IOException -> L29
            r0.append(r1)     // Catch: java.io.IOException -> L29
            r1 = 1
            r6.f7375h = r1     // Catch: java.io.IOException -> L29
        L24:
            java.lang.String r6 = r0.toString()     // Catch: java.io.IOException -> L29
            goto L40
        L29:
            r6 = move-exception
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "(cannot get  info: "
            r0.append(r1)
            r0.append(r6)
            java.lang.String r6 = ")"
            r0.append(r6)
            java.lang.String r6 = r0.toString()
        L40:
            java.lang.String r0 = "\" instead of expected "
            java.lang.String r5 = p005b.p131d.p132a.p133a.C1499a.m583E(r5, r6, r0, r7)
            r3.<init>(r4, r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p295o.p296a.p297a.p298p.C2691b0.<init>(b.o.a.a.p.a0, java.lang.String, b.o.a.a.p.q, java.lang.String):void");
    }

    public C2691b0(C2689a0 c2689a0, Exception exc) {
        super(c2689a0 + " " + exc);
        this.f7361c = null;
        this.f7361c = exc;
    }
}
