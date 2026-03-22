package p448i.p449a.p450a.p451c;

import android.os.Handler;
import android.os.SystemClock;
import java.io.IOException;
import java.util.List;
import me.jessyan.progressmanager.body.ProgressInfo;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p448i.p449a.p450a.InterfaceC4348a;
import p458k.AbstractC4387j0;
import p458k.C4371b0;
import p474l.AbstractC4748j;
import p474l.C4744f;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4762x;

/* renamed from: i.a.a.c.a */
/* loaded from: classes2.dex */
public class C4350a extends AbstractC4387j0 {

    /* renamed from: b */
    public Handler f11216b;

    /* renamed from: c */
    public int f11217c;

    /* renamed from: d */
    public final AbstractC4387j0 f11218d;

    /* renamed from: e */
    public final InterfaceC4348a[] f11219e;

    /* renamed from: f */
    public final ProgressInfo f11220f = new ProgressInfo(System.currentTimeMillis());

    /* renamed from: g */
    public InterfaceC4745g f11221g;

    /* renamed from: i.a.a.c.a$a */
    public final class a extends AbstractC4748j {

        /* renamed from: e */
        public long f11222e;

        /* renamed from: f */
        public long f11223f;

        /* renamed from: g */
        public long f11224g;

        /* renamed from: i.a.a.c.a$a$a, reason: collision with other inner class name */
        public class RunnableC5132a implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ long f11226c;

            /* renamed from: e */
            public final /* synthetic */ long f11227e;

            /* renamed from: f */
            public final /* synthetic */ long f11228f;

            /* renamed from: g */
            public final /* synthetic */ InterfaceC4348a f11229g;

            public RunnableC5132a(long j2, long j3, long j4, InterfaceC4348a interfaceC4348a) {
                this.f11226c = j2;
                this.f11227e = j3;
                this.f11228f = j4;
                this.f11229g = interfaceC4348a;
            }

            @Override // java.lang.Runnable
            public void run() {
                ProgressInfo progressInfo = C4350a.this.f11220f;
                progressInfo.f12635g = this.f11226c;
                long j2 = this.f11227e;
                progressInfo.f12632c = j2;
                progressInfo.f12634f = this.f11228f;
                progressInfo.f12637i = j2 == progressInfo.f12633e;
                this.f11229g.mo198b(progressInfo);
            }
        }

        public a(InterfaceC4762x interfaceC4762x) {
            super(interfaceC4762x);
            this.f11222e = 0L;
            this.f11223f = 0L;
            this.f11224g = 0L;
        }

        @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x
        /* renamed from: x */
        public void mo4923x(C4744f c4744f, long j2) {
            int i2 = 0;
            try {
                super.mo4923x(c4744f, j2);
                C4350a c4350a = C4350a.this;
                ProgressInfo progressInfo = c4350a.f11220f;
                if (progressInfo.f12633e == 0) {
                    progressInfo.f12633e = c4350a.mo4920a();
                }
                this.f11222e += j2;
                this.f11224g += j2;
                if (C4350a.this.f11219e == null) {
                    return;
                }
                long elapsedRealtime = SystemClock.elapsedRealtime();
                long j3 = elapsedRealtime - this.f11223f;
                C4350a c4350a2 = C4350a.this;
                if (j3 < c4350a2.f11217c && this.f11222e != c4350a2.f11220f.f12633e) {
                    return;
                }
                long j4 = this.f11224g;
                long j5 = this.f11222e;
                int i3 = 0;
                while (true) {
                    C4350a c4350a3 = C4350a.this;
                    InterfaceC4348a[] interfaceC4348aArr = c4350a3.f11219e;
                    if (i3 >= interfaceC4348aArr.length) {
                        this.f11223f = elapsedRealtime;
                        this.f11224g = 0L;
                        return;
                    } else {
                        c4350a3.f11216b.post(new RunnableC5132a(j4, j5, j3, interfaceC4348aArr[i3]));
                        i3++;
                        j4 = j4;
                    }
                }
            } catch (IOException e2) {
                e2.printStackTrace();
                while (true) {
                    C4350a c4350a4 = C4350a.this;
                    InterfaceC4348a[] interfaceC4348aArr2 = c4350a4.f11219e;
                    if (i2 >= interfaceC4348aArr2.length) {
                        throw e2;
                    }
                    interfaceC4348aArr2[i2].mo197a(c4350a4.f11220f.f12636h, e2);
                    i2++;
                }
            }
        }
    }

    public C4350a(Handler handler, AbstractC4387j0 abstractC4387j0, List<InterfaceC4348a> list, int i2) {
        this.f11218d = abstractC4387j0;
        this.f11219e = (InterfaceC4348a[]) list.toArray(new InterfaceC4348a[list.size()]);
        this.f11216b = handler;
        this.f11217c = i2;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: a */
    public long mo4920a() {
        try {
            return this.f11218d.mo4920a();
        } catch (IOException e2) {
            e2.printStackTrace();
            return -1L;
        }
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: b */
    public C4371b0 mo4921b() {
        return this.f11218d.mo4921b();
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: d */
    public void mo4922d(InterfaceC4745g interfaceC4745g) {
        if (this.f11221g == null) {
            this.f11221g = C2354n.m2497n(new a(interfaceC4745g));
        }
        try {
            this.f11218d.mo4922d(this.f11221g);
            this.f11221g.flush();
        } catch (IOException e2) {
            e2.printStackTrace();
            int i2 = 0;
            while (true) {
                InterfaceC4348a[] interfaceC4348aArr = this.f11219e;
                if (i2 >= interfaceC4348aArr.length) {
                    throw e2;
                }
                interfaceC4348aArr[i2].mo197a(this.f11220f.f12636h, e2);
                i2++;
            }
        }
    }
}
