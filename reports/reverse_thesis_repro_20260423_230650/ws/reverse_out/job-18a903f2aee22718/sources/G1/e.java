package G1;

import B2.B;
import B2.D;
import B2.H;
import B2.I;
import B2.z;
import Q2.l;
import android.os.Handler;
import android.os.Looper;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public final class e extends I {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final String f863i = "e";

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f864a;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final z f866c;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f868e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private H f869f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private c f870g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private b f871h;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f867d = false;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Handler f865b = new Handler(Looper.getMainLooper());

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            e.this.l();
        }
    }

    public interface b {
        void a();

        void b();
    }

    public interface c {
        void a(l lVar);

        void onMessage(String str);
    }

    public e(String str, c cVar, b bVar) {
        this.f864a = str;
        this.f870g = cVar;
        this.f871h = bVar;
        z.a aVar = new z.a();
        TimeUnit timeUnit = TimeUnit.SECONDS;
        this.f866c = aVar.f(10L, timeUnit).W(10L, timeUnit).S(0L, TimeUnit.MINUTES).c();
    }

    private void h(String str, Throwable th) {
        Y.a.n(f863i, "Error occurred, shutting down websocket connection: " + str, th);
        j();
    }

    private void j() {
        H h3 = this.f869f;
        if (h3 != null) {
            try {
                h3.b(1000, "End of session");
            } catch (Exception unused) {
            }
            this.f869f = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public synchronized void l() {
        if (!this.f867d) {
            k();
        }
    }

    private void m() {
        if (this.f867d) {
            throw new IllegalStateException("Can't reconnect closed client");
        }
        if (!this.f868e) {
            Y.a.I(f863i, "Couldn't connect to \"" + this.f864a + "\", will silently retry");
            this.f868e = true;
        }
        this.f865b.postDelayed(new a(), 2000L);
    }

    @Override // B2.I
    public synchronized void a(H h3, int i3, String str) {
        try {
            this.f869f = null;
            if (!this.f867d) {
                b bVar = this.f871h;
                if (bVar != null) {
                    bVar.a();
                }
                m();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // B2.I
    public synchronized void c(H h3, Throwable th, D d3) {
        try {
            if (this.f869f != null) {
                h("Websocket exception", th);
            }
            if (!this.f867d) {
                b bVar = this.f871h;
                if (bVar != null) {
                    bVar.a();
                }
                m();
            }
        } catch (Throwable th2) {
            throw th2;
        }
    }

    @Override // B2.I
    public synchronized void d(H h3, l lVar) {
        c cVar = this.f870g;
        if (cVar != null) {
            cVar.a(lVar);
        }
    }

    @Override // B2.I
    public synchronized void e(H h3, String str) {
        c cVar = this.f870g;
        if (cVar != null) {
            cVar.onMessage(str);
        }
    }

    @Override // B2.I
    public synchronized void f(H h3, D d3) {
        this.f869f = h3;
        this.f868e = false;
        b bVar = this.f871h;
        if (bVar != null) {
            bVar.b();
        }
    }

    public void i() {
        this.f867d = true;
        j();
        this.f870g = null;
        b bVar = this.f871h;
        if (bVar != null) {
            bVar.a();
        }
    }

    public void k() {
        if (this.f867d) {
            throw new IllegalStateException("Can't connect closed client");
        }
        this.f866c.D(new B.a().m(this.f864a).b(), this);
    }

    public synchronized void n(String str) {
        H h3 = this.f869f;
        if (h3 == null) {
            throw new ClosedChannelException();
        }
        h3.c(str);
    }
}
