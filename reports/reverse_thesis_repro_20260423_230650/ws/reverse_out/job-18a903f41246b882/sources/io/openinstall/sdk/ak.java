package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class ak implements z {
    /* JADX WARN: Removed duplicated region for block: B:38:0x0063 A[PHI: r10
      0x0063: PHI (r10v7 android.database.Cursor) = (r10v6 android.database.Cursor), (r10v8 android.database.Cursor) binds: [B:37:0x0061, B:24:0x0046] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // io.openinstall.sdk.z
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String a(android.content.Context r10) throws java.lang.Throwable {
        /*
            r9 = this;
            r0 = 0
            java.lang.String r1 = "content://com.vivo.vms.IdProvider/IdentifierId/OAID"
            android.net.Uri r3 = android.net.Uri.parse(r1)     // Catch: java.lang.Throwable -> L49 java.lang.Exception -> L59
            android.content.ContentResolver r2 = r10.getContentResolver()     // Catch: java.lang.Throwable -> L49 java.lang.Exception -> L59
            r4 = 0
            r5 = 0
            r6 = 0
            r7 = 0
            android.database.Cursor r10 = r2.query(r3, r4, r5, r6, r7)     // Catch: java.lang.Throwable -> L49 java.lang.Exception -> L59
            if (r10 == 0) goto L40
            r10.moveToFirst()     // Catch: java.lang.Throwable -> L3c java.lang.Exception -> L3e
            java.lang.String r1 = "value"
            int r1 = r10.getColumnIndex(r1)     // Catch: java.lang.Throwable -> L3c java.lang.Exception -> L3e
            if (r1 >= 0) goto L2c
            if (r10 == 0) goto L2b
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L2b
            r10.close()
        L2b:
            return r0
        L2c:
            java.lang.String r0 = r10.getString(r1)     // Catch: java.lang.Throwable -> L3c java.lang.Exception -> L3e
            if (r10 == 0) goto L3b
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L3b
            r10.close()
        L3b:
            return r0
        L3c:
            r0 = move-exception
            goto L4d
        L3e:
            r1 = move-exception
            goto L5b
        L40:
            if (r10 == 0) goto L66
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L66
            goto L63
        L49:
            r10 = move-exception
            r8 = r0
            r0 = r10
            r10 = r8
        L4d:
            if (r10 == 0) goto L58
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L58
            r10.close()
        L58:
            throw r0
        L59:
            r10 = move-exception
            r10 = r0
        L5b:
            if (r10 == 0) goto L66
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L66
        L63:
            r10.close()
        L66:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: io.openinstall.sdk.ak.a(android.content.Context):java.lang.String");
    }
}
