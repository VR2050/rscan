package p476m.p477a.p485b.p488j0.p489h;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4796d;
import p476m.p477a.p485b.InterfaceC4812j;
import p476m.p477a.p485b.InterfaceC4901u;
import p476m.p477a.p485b.p486h0.C4806b;
import p476m.p477a.p485b.p488j0.C4813a;
import p476m.p477a.p485b.p488j0.C4814b;
import p476m.p477a.p485b.p494m0.C4883j;

/* renamed from: m.a.b.j0.h.b */
/* loaded from: classes3.dex */
public class RunnableC4821b implements Runnable {

    /* renamed from: c */
    public final C4806b f12339c;

    /* renamed from: e */
    public final ServerSocket f12340e;

    /* renamed from: f */
    public final C4883j f12341f;

    /* renamed from: g */
    public final InterfaceC4812j<? extends InterfaceC4901u> f12342g;

    /* renamed from: h */
    public final InterfaceC4796d f12343h;

    /* renamed from: i */
    public final ExecutorService f12344i;

    /* renamed from: j */
    public final AtomicBoolean f12345j = new AtomicBoolean(false);

    public RunnableC4821b(C4806b c4806b, ServerSocket serverSocket, C4883j c4883j, InterfaceC4812j<? extends InterfaceC4901u> interfaceC4812j, InterfaceC4796d interfaceC4796d, ExecutorService executorService) {
        this.f12339c = c4806b;
        this.f12340e = serverSocket;
        this.f12342g = interfaceC4812j;
        this.f12341f = c4883j;
        this.f12343h = interfaceC4796d;
        this.f12344i = executorService;
    }

    @Override // java.lang.Runnable
    public void run() {
        while (!this.f12345j.get() && !Thread.interrupted()) {
            try {
                Socket accept = this.f12340e.accept();
                accept.setSoTimeout(this.f12339c.f12287e);
                accept.setKeepAlive(this.f12339c.f12290h);
                accept.setTcpNoDelay(this.f12339c.f12291i);
                int i2 = this.f12339c.f12293k;
                if (i2 > 0) {
                    accept.setReceiveBufferSize(i2);
                }
                int i3 = this.f12339c.f12292j;
                if (i3 > 0) {
                    accept.setSendBufferSize(i3);
                }
                int i4 = this.f12339c.f12289g;
                if (i4 >= 0) {
                    accept.setSoLinger(true, i4);
                }
                Objects.requireNonNull((C4814b) this.f12342g);
                C4813a c4813a = new C4813a(8192, 8192, null, null, null, null, null, null, null);
                C2354n.m2470e1(accept, "Socket");
                c4813a.f12308j.set(accept);
                c4813a.f12302c.f12416g = null;
                c4813a.f12303e.f12425f = null;
                this.f12344i.execute(new RunnableC4825f(this.f12341f, c4813a, this.f12343h));
            } catch (Exception e2) {
                this.f12343h.mo5471a(e2);
                return;
            }
        }
    }
}
