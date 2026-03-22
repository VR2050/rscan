package p448i.p449a.p450a.p451c;

import android.os.SystemClock;
import java.io.IOException;
import me.jessyan.progressmanager.body.ProgressInfo;
import p448i.p449a.p450a.InterfaceC4348a;
import p474l.AbstractC4749k;
import p474l.C4744f;
import p474l.InterfaceC4764z;

/* renamed from: i.a.a.c.b */
/* loaded from: classes2.dex */
public class C4351b extends AbstractC4749k {

    /* renamed from: e */
    public long f11231e;

    /* renamed from: f */
    public long f11232f;

    /* renamed from: g */
    public long f11233g;

    /* renamed from: h */
    public final /* synthetic */ C4352c f11234h;

    /* renamed from: i.a.a.c.b$a */
    public class a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ long f11235c;

        /* renamed from: e */
        public final /* synthetic */ long f11236e;

        /* renamed from: f */
        public final /* synthetic */ long f11237f;

        /* renamed from: g */
        public final /* synthetic */ long f11238g;

        /* renamed from: h */
        public final /* synthetic */ InterfaceC4348a f11239h;

        public a(long j2, long j3, long j4, long j5, InterfaceC4348a interfaceC4348a) {
            this.f11235c = j2;
            this.f11236e = j3;
            this.f11237f = j4;
            this.f11238g = j5;
            this.f11239h = interfaceC4348a;
        }

        @Override // java.lang.Runnable
        public void run() {
            ProgressInfo progressInfo = C4351b.this.f11234h.f11245i;
            long j2 = this.f11235c;
            progressInfo.f12635g = j2 != -1 ? this.f11236e : -1L;
            long j3 = this.f11237f;
            progressInfo.f12632c = j3;
            progressInfo.f12634f = this.f11238g;
            progressInfo.f12637i = j2 == -1 && j3 == progressInfo.f12633e;
            this.f11239h.mo198b(progressInfo);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4351b(C4352c c4352c, InterfaceC4764z interfaceC4764z) {
        super(interfaceC4764z);
        this.f11234h = c4352c;
        this.f11231e = 0L;
        this.f11232f = 0L;
        this.f11233g = 0L;
    }

    @Override // p474l.AbstractC4749k, p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(C4744f c4744f, long j2) {
        long j3;
        C4351b c4351b = this;
        int i2 = 0;
        try {
            long mo4924J = super.mo4924J(c4744f, j2);
            C4352c c4352c = c4351b.f11234h;
            ProgressInfo progressInfo = c4352c.f11245i;
            if (progressInfo.f12633e == 0) {
                progressInfo.f12633e = c4352c.mo4925d();
            }
            c4351b.f11231e += mo4924J != -1 ? mo4924J : 0L;
            c4351b.f11233g += mo4924J != -1 ? mo4924J : 0L;
            if (c4351b.f11234h.f11244h != null) {
                long elapsedRealtime = SystemClock.elapsedRealtime();
                long j4 = elapsedRealtime - c4351b.f11232f;
                C4352c c4352c2 = c4351b.f11234h;
                if (j4 >= c4352c2.f11242f || mo4924J == -1 || c4351b.f11231e == c4352c2.f11245i.f12633e) {
                    long j5 = c4351b.f11233g;
                    long j6 = c4351b.f11231e;
                    int i3 = 0;
                    while (true) {
                        C4352c c4352c3 = c4351b.f11234h;
                        InterfaceC4348a[] interfaceC4348aArr = c4352c3.f11244h;
                        if (i3 >= interfaceC4348aArr.length) {
                            break;
                        }
                        long j7 = j6;
                        c4352c3.f11241e.post(new a(mo4924J, j5, j7, j4, interfaceC4348aArr[i3]));
                        i3++;
                        c4351b = this;
                        elapsedRealtime = elapsedRealtime;
                        j6 = j7;
                        mo4924J = mo4924J;
                    }
                    C4351b c4351b2 = c4351b;
                    j3 = mo4924J;
                    c4351b2.f11232f = elapsedRealtime;
                    c4351b2.f11233g = 0L;
                    return j3;
                }
            }
            j3 = mo4924J;
            return j3;
        } catch (IOException e2) {
            e2.printStackTrace();
            while (true) {
                C4352c c4352c4 = c4351b.f11234h;
                InterfaceC4348a[] interfaceC4348aArr2 = c4352c4.f11244h;
                if (i2 >= interfaceC4348aArr2.length) {
                    throw e2;
                }
                interfaceC4348aArr2[i2].mo197a(c4352c4.f11245i.f12636h, e2);
                i2++;
            }
        }
    }
}
