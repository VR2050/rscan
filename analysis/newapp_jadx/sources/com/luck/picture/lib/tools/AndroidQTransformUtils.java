package com.luck.picture.lib.tools;

import android.content.Context;
import android.net.Uri;
import java.io.File;

/* loaded from: classes2.dex */
public class AndroidQTransformUtils {
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0046, code lost:
    
        if (r3 != false) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x005d, code lost:
    
        com.luck.picture.lib.tools.PictureFileUtils.close(r2);
        r2 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x005b, code lost:
    
        if (r3 != false) goto L26;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0 */
    /* JADX WARN: Type inference failed for: r0v1, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r0v2 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v12, types: [java.io.Closeable, l.h] */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v8, types: [java.io.Closeable] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String copyPathToAndroidQ(android.content.Context r2, java.lang.String r3, int r4, int r5, java.lang.String r6, java.lang.String r7) {
        /*
            r0 = 0
            android.net.Uri r1 = android.net.Uri.parse(r3)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            java.lang.String r3 = com.luck.picture.lib.tools.StringUtils.getEncryptionValue(r3, r4, r5)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            java.lang.String r3 = com.luck.picture.lib.tools.PictureFileUtils.createFilePath(r2, r3, r6, r7)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            java.io.File r4 = new java.io.File     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            r4.<init>(r3)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            boolean r5 = r4.exists()     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            if (r5 == 0) goto L19
            return r3
        L19:
            android.content.ContentResolver r2 = r2.getContentResolver()     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            java.io.InputStream r2 = r2.openInputStream(r1)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            java.util.Objects.requireNonNull(r2)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            l.z r2 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2397H1(r2)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            l.h r2 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2500o(r2)     // Catch: java.lang.Throwable -> L4b java.lang.Exception -> L4d
            boolean r4 = com.luck.picture.lib.tools.PictureFileUtils.bufferCopy(r2, r4)     // Catch: java.lang.Exception -> L49 java.lang.Throwable -> L61
            if (r4 == 0) goto L3f
            r4 = r2
            l.t r4 = (p474l.C4758t) r4
            boolean r4 = r4.isOpen()
            if (r4 == 0) goto L3e
            com.luck.picture.lib.tools.PictureFileUtils.close(r2)
        L3e:
            return r3
        L3f:
            r3 = r2
            l.t r3 = (p474l.C4758t) r3
            boolean r3 = r3.isOpen()
            if (r3 == 0) goto L60
            goto L5d
        L49:
            r3 = move-exception
            goto L4f
        L4b:
            r3 = move-exception
            goto L63
        L4d:
            r3 = move-exception
            r2 = r0
        L4f:
            r3.printStackTrace()     // Catch: java.lang.Throwable -> L61
            if (r2 == 0) goto L60
            r3 = r2
            l.t r3 = (p474l.C4758t) r3
            boolean r3 = r3.isOpen()
            if (r3 == 0) goto L60
        L5d:
            com.luck.picture.lib.tools.PictureFileUtils.close(r2)
        L60:
            return r0
        L61:
            r3 = move-exception
            r0 = r2
        L63:
            if (r0 == 0) goto L71
            r2 = r0
            l.t r2 = (p474l.C4758t) r2
            boolean r2 = r2.isOpen()
            if (r2 == 0) goto L71
            com.luck.picture.lib.tools.PictureFileUtils.close(r0)
        L71:
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.tools.AndroidQTransformUtils.copyPathToAndroidQ(android.content.Context, java.lang.String, int, int, java.lang.String, java.lang.String):java.lang.String");
    }

    public static boolean copyPathToDCIM(Context context, File file, Uri uri) {
        try {
            return PictureFileUtils.bufferCopy(file, context.getContentResolver().openOutputStream(uri));
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }
}
