package p005b.p113c0.p114a.p124i.p127p;

import android.content.Context;
import java.io.File;

/* renamed from: b.c0.a.i.p.d */
/* loaded from: classes2.dex */
public class C1481d {

    /* renamed from: a */
    public C1482e f1474a;

    public C1481d(Context context) {
        new C1479b();
        this.f1474a = new C1482e(new File(context.getCacheDir(), "_andserver_session_"));
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x003a A[Catch: all -> 0x0066, IOException -> 0x0068, TryCatch #0 {IOException -> 0x0068, blocks: (B:12:0x0020, B:14:0x0028, B:20:0x003a, B:22:0x0047, B:26:0x0053, B:43:0x0030, B:44:0x0033), top: B:11:0x0020 }] */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m558a(@androidx.annotation.NonNull p005b.p113c0.p114a.p124i.p127p.InterfaceC1478a r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof p005b.p113c0.p114a.p124i.p127p.C1480c
            if (r0 == 0) goto L85
            boolean r0 = r6.mo556a()
            if (r0 == 0) goto L85
            b.c0.a.i.p.c r6 = (p005b.p113c0.p114a.p124i.p127p.C1480c) r6
            r0 = 0
            r6.f1472c = r0
            b.c0.a.i.p.e r1 = r5.f1474a
            java.util.Objects.requireNonNull(r1)
            java.lang.String r2 = "The session can not be null."
            p005b.p199l.p200a.p201a.p250p1.C2354n.m2474f1(r6, r2)
            r2 = 0
            boolean r3 = android.text.TextUtils.isEmpty(r2)
            if (r3 != 0) goto L7d
            java.io.File r3 = r1.f1475a     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            boolean r4 = r3.exists()     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            if (r4 == 0) goto L33
            boolean r4 = r3.isDirectory()     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            if (r4 == 0) goto L30
            r3 = 1
            goto L37
        L30:
            r3.delete()     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
        L33:
            boolean r3 = r3.mkdirs()     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
        L37:
            if (r3 != 0) goto L3a
            goto L85
        L3a:
            java.io.File r3 = new java.io.File     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            java.io.File r4 = r1.f1475a     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            r3.<init>(r4, r2)     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            boolean r4 = r3.exists()     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            if (r4 == 0) goto L4a
            p005b.p113c0.p114a.p130l.C1492d.m562a(r3)     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
        L4a:
            boolean r0 = r3.createNewFile()     // Catch: java.io.IOException -> L4f java.lang.Throwable -> L66
            goto L50
        L4f:
        L50:
            if (r0 != 0) goto L53
            goto L85
        L53:
            java.io.ObjectOutputStream r0 = new java.io.ObjectOutputStream     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            java.io.FileOutputStream r4 = new java.io.FileOutputStream     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            r4.<init>(r3)     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            r0.<init>(r4)     // Catch: java.lang.Throwable -> L66 java.io.IOException -> L68
            r6.m557b(r0)     // Catch: java.io.IOException -> L64 java.lang.Throwable -> L75
            r0.close()     // Catch: java.lang.Exception -> L85
            goto L85
        L64:
            r6 = move-exception
            goto L6a
        L66:
            r6 = move-exception
            goto L77
        L68:
            r6 = move-exception
            r0 = r2
        L6a:
            java.io.File r3 = new java.io.File     // Catch: java.lang.Throwable -> L75
            java.io.File r1 = r1.f1475a     // Catch: java.lang.Throwable -> L75
            r3.<init>(r1, r2)     // Catch: java.lang.Throwable -> L75
            p005b.p113c0.p114a.p130l.C1492d.m562a(r3)     // Catch: java.lang.Throwable -> L75
            throw r6     // Catch: java.lang.Throwable -> L75
        L75:
            r6 = move-exception
            r2 = r0
        L77:
            if (r2 == 0) goto L7c
            r2.close()     // Catch: java.lang.Exception -> L7c
        L7c:
            throw r6
        L7d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "The session id can not be empty or null."
            r6.<init>(r0)
            throw r6
        L85:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p113c0.p114a.p124i.p127p.C1481d.m558a(b.c0.a.i.p.a):void");
    }
}
