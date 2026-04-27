package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class ag implements z {
    /* JADX WARN: Removed duplicated region for block: B:38:0x0068 A[PHI: r10
      0x0068: PHI (r10v7 android.database.Cursor) = (r10v6 android.database.Cursor), (r10v9 android.database.Cursor) binds: [B:37:0x0066, B:24:0x004b] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // io.openinstall.sdk.z
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String a(android.content.Context r10) throws java.lang.Throwable {
        /*
            r9 = this;
            r0 = 0
            java.lang.String r1 = "content://com.meizu.flyme.openidsdk/"
            android.net.Uri r3 = android.net.Uri.parse(r1)     // Catch: java.lang.Throwable -> L4e java.lang.Exception -> L5e
            android.content.ContentResolver r2 = r10.getContentResolver()     // Catch: java.lang.Throwable -> L4e java.lang.Exception -> L5e
            r4 = 0
            r5 = 0
            java.lang.String r10 = "oaid"
            java.lang.String[] r6 = new java.lang.String[]{r10}     // Catch: java.lang.Throwable -> L4e java.lang.Exception -> L5e
            r7 = 0
            android.database.Cursor r10 = r2.query(r3, r4, r5, r6, r7)     // Catch: java.lang.Throwable -> L4e java.lang.Exception -> L5e
            if (r10 == 0) goto L45
            r10.moveToFirst()     // Catch: java.lang.Throwable -> L41 java.lang.Exception -> L43
            java.lang.String r1 = "value"
            int r1 = r10.getColumnIndex(r1)     // Catch: java.lang.Throwable -> L41 java.lang.Exception -> L43
            if (r1 >= 0) goto L31
            if (r10 == 0) goto L30
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L30
            r10.close()
        L30:
            return r0
        L31:
            java.lang.String r0 = r10.getString(r1)     // Catch: java.lang.Throwable -> L41 java.lang.Exception -> L43
            if (r10 == 0) goto L40
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L40
            r10.close()
        L40:
            return r0
        L41:
            r0 = move-exception
            goto L52
        L43:
            r1 = move-exception
            goto L60
        L45:
            if (r10 == 0) goto L6b
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L6b
            goto L68
        L4e:
            r10 = move-exception
            r8 = r0
            r0 = r10
            r10 = r8
        L52:
            if (r10 == 0) goto L5d
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L5d
            r10.close()
        L5d:
            throw r0
        L5e:
            r10 = move-exception
            r10 = r0
        L60:
            if (r10 == 0) goto L6b
            boolean r1 = r10.isClosed()
            if (r1 != 0) goto L6b
        L68:
            r10.close()
        L6b:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: io.openinstall.sdk.ag.a(android.content.Context):java.lang.String");
    }
}
