package p005b.p295o.p296a.p297a;

/* renamed from: b.o.a.a.j */
/* loaded from: classes2.dex */
public class C2682j extends Exception {

    /* renamed from: c */
    public Throwable f7336c;

    public C2682j(String str, Throwable th) {
        super(str + " " + th);
        this.f7336c = null;
        this.f7336c = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.f7336c;
    }

    public C2682j(C2674b c2674b, String str, int i2, int i3, String str2, String str3) {
        this(str, i2, i3, str2, str3);
        c2674b.m3166a(str3, str, i2);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2682j(p005b.p295o.p296a.p297a.C2681i r5, char r6, char[] r7) {
        /*
            r4 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "got '"
            r0.append(r1)
            r0.append(r6)
            java.lang.String r6 = "' instead of "
            r0.append(r6)
            java.lang.StringBuffer r6 = new java.lang.StringBuffer
            r6.<init>()
            r1 = 0
            char r1 = r7[r1]
            r6.append(r1)
            r1 = 1
        L1e:
            int r2 = r7.length
            if (r1 >= r2) goto L36
            java.lang.String r2 = "or "
            java.lang.StringBuilder r2 = p005b.p131d.p132a.p133a.C1499a.m586H(r2)
            char r3 = r7[r1]
            r2.append(r3)
            java.lang.String r2 = r2.toString()
            r6.append(r2)
            int r1 = r1 + 1
            goto L1e
        L36:
            java.lang.String r6 = r6.toString()
            r0.append(r6)
            java.lang.String r6 = r0.toString()
            r4.<init>(r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p295o.p296a.p297a.C2682j.<init>(b.o.a.a.i, char, char[]):void");
    }

    public C2682j(C2681i c2681i, String str, char[] cArr) {
        this(c2681i, "got \"" + str + "\" instead of \"" + new String(cArr) + "\" as expected");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2682j(java.lang.String r2, int r3, int r4, java.lang.String r5, java.lang.String r6) {
        /*
            r1 = this;
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            r0.append(r2)
            java.lang.String r2 = "("
            r0.append(r2)
            r0.append(r3)
            java.lang.String r2 = "): \n"
            r0.append(r2)
            r0.append(r5)
            java.lang.String r2 = "\nLast character read was '"
            r0.append(r2)
            r2 = -1
            if (r4 != r2) goto L23
            java.lang.String r2 = "EOF"
            goto L31
        L23:
            java.lang.String r2 = ""
            java.lang.StringBuilder r2 = p005b.p131d.p132a.p133a.C1499a.m586H(r2)
            char r3 = (char) r4
            r2.append(r3)
            java.lang.String r2 = r2.toString()
        L31:
            java.lang.String r3 = "'\n"
            java.lang.String r2 = p005b.p131d.p132a.p133a.C1499a.m583E(r0, r2, r3, r6)
            r1.<init>(r2)
            r2 = 0
            r1.f7336c = r2
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p295o.p296a.p297a.C2682j.<init>(java.lang.String, int, int, java.lang.String, java.lang.String):void");
    }

    public C2682j(C2681i c2681i, String str) {
        this(c2681i.f7321B, c2681i.f7332w, c2681i.f7330K, c2681i.f7323D, "", str);
    }
}
