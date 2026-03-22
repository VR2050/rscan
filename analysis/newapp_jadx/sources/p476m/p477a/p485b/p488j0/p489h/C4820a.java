package p476m.p477a.p485b.p488j0.p489h;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import p005b.p113c0.p114a.p129k.AbstractC1487c;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p485b.InterfaceC4796d;
import p476m.p477a.p485b.InterfaceC4812j;
import p476m.p477a.p485b.p486h0.C4806b;
import p476m.p477a.p485b.p488j0.C4813a;
import p476m.p477a.p485b.p488j0.C4814b;
import p476m.p477a.p485b.p494m0.C4883j;

/* renamed from: m.a.b.j0.h.a */
/* loaded from: classes3.dex */
public class C4820a {

    /* renamed from: a */
    public final int f12322a;

    /* renamed from: b */
    public final InetAddress f12323b;

    /* renamed from: c */
    public final C4806b f12324c;

    /* renamed from: d */
    public final ServerSocketFactory f12325d;

    /* renamed from: e */
    public final C4883j f12326e;

    /* renamed from: f */
    public final InterfaceC4822c f12327f;

    /* renamed from: g */
    public final InterfaceC4796d f12328g;

    /* renamed from: h */
    public final ThreadPoolExecutor f12329h;

    /* renamed from: i */
    public final ThreadGroup f12330i;

    /* renamed from: j */
    public final C4826g f12331j;

    /* renamed from: k */
    public final AtomicReference<a> f12332k;

    /* renamed from: l */
    public volatile ServerSocket f12333l;

    /* renamed from: m */
    public volatile RunnableC4821b f12334m;

    /* renamed from: m.a.b.j0.h.a$a */
    public enum a {
        READY,
        ACTIVE,
        STOPPING
    }

    public C4820a(int i2, InetAddress inetAddress, C4806b c4806b, ServerSocketFactory serverSocketFactory, C4883j c4883j, InterfaceC4812j<? extends C4813a> interfaceC4812j, InterfaceC4822c interfaceC4822c, InterfaceC4796d interfaceC4796d) {
        this.f12322a = i2;
        this.f12323b = inetAddress;
        this.f12324c = c4806b;
        this.f12325d = serverSocketFactory;
        this.f12326e = c4883j;
        this.f12327f = interfaceC4822c;
        this.f12328g = interfaceC4796d;
        this.f12329h = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new SynchronousQueue(), new ThreadFactoryC4824e(C1499a.m626l("HTTP-listener-", i2)));
        ThreadGroup threadGroup = new ThreadGroup("HTTP-workers");
        this.f12330i = threadGroup;
        this.f12331j = new C4826g(0, Integer.MAX_VALUE, 1L, TimeUnit.SECONDS, new SynchronousQueue(), new ThreadFactoryC4824e("HTTP-worker", threadGroup));
        this.f12332k = new AtomicReference<>(a.READY);
    }

    /* renamed from: a */
    public void m5488a(long j2, TimeUnit timeUnit) {
        if (this.f12332k.compareAndSet(a.ACTIVE, a.STOPPING)) {
            this.f12329h.shutdown();
            this.f12331j.shutdown();
            RunnableC4821b runnableC4821b = this.f12334m;
            if (runnableC4821b != null) {
                try {
                    if (runnableC4821b.f12345j.compareAndSet(false, true)) {
                        runnableC4821b.f12340e.close();
                    }
                } catch (IOException e2) {
                    this.f12328g.mo5471a(e2);
                }
            }
            this.f12330i.interrupt();
        }
        if (j2 > 0) {
            try {
                this.f12331j.awaitTermination(j2, timeUnit);
            } catch (InterruptedException unused) {
                Thread.currentThread().interrupt();
            }
        }
        C4826g c4826g = this.f12331j;
        Objects.requireNonNull(c4826g);
        Iterator it = new HashSet(c4826g.f12361c.keySet()).iterator();
        while (it.hasNext()) {
            try {
                ((RunnableC4825f) it.next()).f12359e.shutdown();
            } catch (IOException e3) {
                this.f12328g.mo5471a(e3);
            }
        }
    }

    /* renamed from: b */
    public void m5489b() {
        if (this.f12332k.compareAndSet(a.READY, a.ACTIVE)) {
            this.f12333l = this.f12325d.createServerSocket();
            this.f12333l.setReuseAddress(this.f12324c.f12288f);
            this.f12333l.bind(new InetSocketAddress(this.f12323b, this.f12322a), this.f12324c.f12294l);
            if (this.f12324c.f12293k > 0) {
                this.f12333l.setReceiveBufferSize(this.f12324c.f12293k);
            }
            if (this.f12327f == null || !(this.f12333l instanceof SSLServerSocket)) {
                this.f12334m = new RunnableC4821b(this.f12324c, this.f12333l, this.f12326e, C4814b.f12311a, this.f12328g, this.f12331j);
                this.f12329h.execute(this.f12334m);
            } else {
                InterfaceC4822c interfaceC4822c = this.f12327f;
                Objects.requireNonNull((AbstractC1487c.b) interfaceC4822c);
                throw null;
            }
        }
    }
}
