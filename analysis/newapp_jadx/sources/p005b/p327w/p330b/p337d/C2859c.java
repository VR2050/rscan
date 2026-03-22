package p005b.p327w.p330b.p337d;

import android.os.Handler;
import android.os.Looper;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import me.jessyan.progressmanager.body.ProgressInfo;
import p448i.p449a.p450a.C4349b;
import p448i.p449a.p450a.InterfaceC4348a;
import p458k.C4375d0;
import p458k.C4379f0;
import p458k.C4381g0;
import p458k.InterfaceC4369a0;
import p458k.InterfaceC4378f;
import p458k.InterfaceC4380g;

/* renamed from: b.w.b.d.c */
/* loaded from: classes2.dex */
public class C2859c {

    /* renamed from: a */
    public static C2859c f7782a;

    /* renamed from: b */
    public C4375d0 f7783b;

    /* renamed from: c */
    public Handler f7784c = new Handler(Looper.getMainLooper());

    /* renamed from: b.w.b.d.c$a */
    public class a implements InterfaceC4380g {

        /* renamed from: a */
        public final /* synthetic */ c f7785a;

        /* renamed from: b */
        public final /* synthetic */ String f7786b;

        /* renamed from: c */
        public final /* synthetic */ String f7787c;

        /* renamed from: b.w.b.d.c$a$a, reason: collision with other inner class name */
        public class RunnableC5116a implements Runnable {
            public RunnableC5116a() {
            }

            @Override // java.lang.Runnable
            public void run() {
                a.this.f7785a.onDownloadSuccess();
            }
        }

        public a(c cVar, String str, String str2) {
            this.f7785a = cVar;
            this.f7786b = str;
            this.f7787c = str2;
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Removed duplicated region for block: B:45:0x0082 A[EXC_TOP_SPLITTER, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:51:? A[SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:52:0x007b A[EXC_TOP_SPLITTER, SYNTHETIC] */
        /* JADX WARN: Type inference failed for: r2v0 */
        /* JADX WARN: Type inference failed for: r2v1, types: [java.io.FileOutputStream] */
        /* JADX WARN: Type inference failed for: r2v5, types: [java.io.FileOutputStream] */
        /* JADX WARN: Type inference failed for: r7v1 */
        /* JADX WARN: Type inference failed for: r7v2 */
        /* JADX WARN: Type inference failed for: r7v3, types: [java.io.FileOutputStream] */
        /* JADX WARN: Type inference failed for: r7v4 */
        /* JADX WARN: Type inference failed for: r7v8 */
        /* JADX WARN: Type inference failed for: r7v9 */
        @Override // p458k.InterfaceC4380g
        /* renamed from: a */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void mo195a(p458k.InterfaceC4378f r6, p458k.C4389k0 r7) {
            /*
                r5 = this;
                r6 = 2048(0x800, float:2.87E-42)
                byte[] r6 = new byte[r6]
                r0 = 0
                k.m0 r7 = r7.f11491k     // Catch: java.lang.Throwable -> L5d java.lang.Exception -> L60
                l.h r7 = r7.mo4927k()     // Catch: java.lang.Throwable -> L5d java.lang.Exception -> L60
                java.io.InputStream r7 = r7.mo5364R()     // Catch: java.lang.Throwable -> L5d java.lang.Exception -> L60
                java.io.File r1 = new java.io.File     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                java.lang.String r2 = r5.f7786b     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                java.lang.String r3 = r5.f7787c     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                r1.<init>(r2, r3)     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                java.io.File r2 = r1.getParentFile()     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                boolean r2 = r2.exists()     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                if (r2 != 0) goto L29
                java.io.File r2 = r1.getParentFile()     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                r2.mkdirs()     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
            L29:
                java.io.FileOutputStream r2 = new java.io.FileOutputStream     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
                r2.<init>(r1)     // Catch: java.lang.Throwable -> L53 java.lang.Exception -> L58
            L2e:
                int r0 = r7.read(r6)     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                r1 = -1
                if (r0 == r1) goto L3a
                r1 = 0
                r2.write(r6, r1, r0)     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                goto L2e
            L3a:
                r2.flush()     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                b.w.b.d.c r6 = p005b.p327w.p330b.p337d.C2859c.this     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                android.os.Handler r6 = r6.f7784c     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                b.w.b.d.c$a$a r0 = new b.w.b.d.c$a$a     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                r0.<init>()     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                r6.post(r0)     // Catch: java.lang.Throwable -> L4d java.lang.Exception -> L50
                r7.close()     // Catch: java.io.IOException -> L74
                goto L74
            L4d:
                r6 = move-exception
                r0 = r2
                goto L54
            L50:
                r6 = move-exception
                r0 = r2
                goto L59
            L53:
                r6 = move-exception
            L54:
                r4 = r0
                r0 = r7
                r7 = r4
                goto L79
            L58:
                r6 = move-exception
            L59:
                r4 = r0
                r0 = r7
                r7 = r4
                goto L62
            L5d:
                r6 = move-exception
                r7 = r0
                goto L79
            L60:
                r6 = move-exception
                r7 = r0
            L62:
                r6.getMessage()     // Catch: java.lang.Throwable -> L78
                b.w.b.d.c$c r6 = r5.f7785a     // Catch: java.lang.Throwable -> L78
                r6.onDownloadFailed()     // Catch: java.lang.Throwable -> L78
                if (r0 == 0) goto L71
                r0.close()     // Catch: java.io.IOException -> L70
                goto L71
            L70:
            L71:
                if (r7 == 0) goto L77
                r2 = r7
            L74:
                r2.close()     // Catch: java.io.IOException -> L77
            L77:
                return
            L78:
                r6 = move-exception
            L79:
                if (r0 == 0) goto L80
                r0.close()     // Catch: java.io.IOException -> L7f
                goto L80
            L7f:
            L80:
                if (r7 == 0) goto L85
                r7.close()     // Catch: java.io.IOException -> L85
            L85:
                throw r6
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p327w.p330b.p337d.C2859c.a.mo195a(k.f, k.k0):void");
        }

        @Override // p458k.InterfaceC4380g
        /* renamed from: b */
        public void mo196b(InterfaceC4378f interfaceC4378f, IOException iOException) {
            this.f7785a.onDownloadFailed();
        }
    }

    /* renamed from: b.w.b.d.c$b */
    public class b implements InterfaceC4348a {

        /* renamed from: a */
        public final /* synthetic */ c f7790a;

        public b(C2859c c2859c, c cVar) {
            this.f7790a = cVar;
        }

        @Override // p448i.p449a.p450a.InterfaceC4348a
        /* renamed from: a */
        public void mo197a(long j2, Exception exc) {
            this.f7790a.onDownloadFailed();
        }

        @Override // p448i.p449a.p450a.InterfaceC4348a
        /* renamed from: b */
        public void mo198b(ProgressInfo progressInfo) {
            this.f7790a.onDownloading(progressInfo);
        }
    }

    /* renamed from: b.w.b.d.c$c */
    public interface c {
        void onDownloadFailed();

        void onDownloadSuccess();

        void onDownloadSuccessData(String str);

        void onDownloading(ProgressInfo progressInfo);
    }

    public C2859c() {
        C4375d0.a aVar = new C4375d0.a();
        InterfaceC4369a0 interceptor = C4349b.m4917b().f11213f;
        Intrinsics.checkParameterIsNotNull(interceptor, "interceptor");
        aVar.f11390d.add(interceptor);
        this.f7783b = new C4375d0(aVar);
    }

    /* renamed from: a */
    public void m3302a(String str, String str2, String str3, c cVar) {
        C4381g0.a aVar = new C4381g0.a();
        aVar.m4978h(str);
        ((C4379f0) this.f7783b.mo4955a(aVar.m4972b())).mo4964k(new a(cVar, str2, str3));
        C4349b.m4917b().m4918a(str, new b(this, cVar));
    }
}
