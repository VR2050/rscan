package p005b.p085c.p088b.p095f;

/* renamed from: b.c.b.f.b */
/* loaded from: classes.dex */
public final class C1364b {
    /* JADX WARN: Code restructure failed: missing block: B:31:0x005d, code lost:
    
        if (r2 == null) goto L30;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Not initialized variable reg: 2, insn: 0x0064: MOVE (r1 I:??[OBJECT, ARRAY]) = (r2 I:??[OBJECT, ARRAY]), block:B:59:0x0064 */
    /* JADX WARN: Removed duplicated region for block: B:43:0x006f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:49:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0068 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r0v0, types: [int] */
    /* JADX WARN: Type inference failed for: r0v2 */
    /* JADX WARN: Type inference failed for: r0v5 */
    /* JADX WARN: Type inference failed for: r0v6, types: [java.io.ByteArrayOutputStream] */
    /* JADX WARN: Type inference failed for: r0v7, types: [java.io.ByteArrayOutputStream, java.io.OutputStream] */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static byte[] m396a(byte[]... r11) {
        /*
            int r0 = r11.length
            r1 = 0
            if (r0 != 0) goto L5
            return r1
        L5:
            java.io.ByteArrayOutputStream r0 = new java.io.ByteArrayOutputStream     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
            r0.<init>()     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
            java.io.DataOutputStream r2 = new java.io.DataOutputStream     // Catch: java.lang.Throwable -> L45 java.lang.Exception -> L4a
            r2.<init>(r0)     // Catch: java.lang.Throwable -> L45 java.lang.Exception -> L4a
            int r3 = r11.length     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            r4 = 0
            r5 = 0
        L12:
            if (r5 >= r3) goto L37
            r6 = r11[r5]     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            int r7 = r6.length     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            java.util.Locale r8 = java.util.Locale.getDefault()     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            r9 = 1
            java.lang.Object[] r9 = new java.lang.Object[r9]     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            java.lang.Integer r7 = java.lang.Integer.valueOf(r7)     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            r9[r4] = r7     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            java.lang.String r7 = "%05d"
            java.lang.String r7 = java.lang.String.format(r8, r7, r9)     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            byte[] r7 = r7.getBytes()     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            r2.write(r7)     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            r2.write(r6)     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            int r5 = r5 + 1
            goto L12
        L37:
            r2.flush()     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            byte[] r11 = r0.toByteArray()     // Catch: java.lang.Exception -> L43 java.lang.Throwable -> L63
            r0.close()     // Catch: java.lang.Exception -> L41
        L41:
            r1 = r11
            goto L5f
        L43:
            r11 = move-exception
            goto L53
        L45:
            r11 = move-exception
        L46:
            r10 = r1
            r1 = r0
            r0 = r10
            goto L66
        L4a:
            r11 = move-exception
            r2 = r1
            goto L53
        L4d:
            r11 = move-exception
            r0 = r1
            goto L66
        L50:
            r11 = move-exception
            r0 = r1
            r2 = r0
        L53:
            p403d.p404a.p405a.p407b.p408a.C4195m.m4816l(r11)     // Catch: java.lang.Throwable -> L63
            if (r0 == 0) goto L5d
            r0.close()     // Catch: java.lang.Exception -> L5c
            goto L5d
        L5c:
        L5d:
            if (r2 == 0) goto L62
        L5f:
            r2.close()     // Catch: java.lang.Exception -> L62
        L62:
            return r1
        L63:
            r11 = move-exception
            r1 = r2
            goto L46
        L66:
            if (r1 == 0) goto L6d
            r1.close()     // Catch: java.lang.Exception -> L6c
            goto L6d
        L6c:
        L6d:
            if (r0 == 0) goto L72
            r0.close()     // Catch: java.lang.Exception -> L72
        L72:
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p088b.p095f.C1364b.m396a(byte[][]):byte[]");
    }
}
