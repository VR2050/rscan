package p005b.p113c0.p114a.p129k;

import com.qunidayede.service.CoreService;
import com.qunidayede.service.ServerManager;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import p005b.p113c0.p114a.C1409a;
import p005b.p113c0.p114a.C1410b;
import p005b.p113c0.p114a.C1412d;
import p005b.p113c0.p114a.InterfaceC1414f;
import p005b.p113c0.p114a.p129k.AbstractC1487c;
import p005b.p113c0.p114a.p130l.C1490b;
import p005b.p327w.p328a.C2825e;
import p476m.p477a.p485b.InterfaceC4796d;
import p476m.p477a.p485b.p486h0.C4806b;
import p476m.p477a.p485b.p488j0.p489h.C4823d;

/* renamed from: b.c0.a.k.a */
/* loaded from: classes2.dex */
public class RunnableC1485a implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ AbstractC1487c f1476c;

    /* renamed from: b.c0.a.k.a$a */
    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Enumeration<NetworkInterface> enumeration;
            InterfaceC1414f.a aVar = RunnableC1485a.this.f1476c.f1485c;
            if (aVar != null) {
                CoreService.C4029a c4029a = (CoreService.C4029a) aVar;
                Objects.requireNonNull(c4029a);
                Pattern pattern = C2825e.f7669a;
                InetAddress inetAddress = null;
                try {
                    enumeration = NetworkInterface.getNetworkInterfaces();
                } catch (SocketException e2) {
                    e2.printStackTrace();
                    enumeration = null;
                }
                if (enumeration != null) {
                    loop0: while (true) {
                        if (!enumeration.hasMoreElements()) {
                            break;
                        }
                        Enumeration<InetAddress> inetAddresses = enumeration.nextElement().getInetAddresses();
                        if (inetAddresses != null) {
                            while (inetAddresses.hasMoreElements()) {
                                InetAddress nextElement = inetAddresses.nextElement();
                                if (!nextElement.isLoopbackAddress()) {
                                    if (C2825e.f7669a.matcher(nextElement.getHostAddress()).matches()) {
                                        inetAddress = nextElement;
                                        break loop0;
                                    }
                                }
                            }
                        }
                    }
                }
                if (inetAddress != null) {
                    ServerManager.m4566a(CoreService.this, 1, inetAddress.getHostAddress());
                }
            }
        }
    }

    /* renamed from: b.c0.a.k.a$b */
    public class b extends Thread {
        public b() {
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            RunnableC1485a.this.f1476c.f1486d.m5488a(3L, TimeUnit.SECONDS);
        }
    }

    /* renamed from: b.c0.a.k.a$c */
    public class c implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ Exception f1479c;

        public c(Exception exc) {
            this.f1479c = exc;
        }

        @Override // java.lang.Runnable
        public void run() {
            InterfaceC1414f.a aVar = RunnableC1485a.this.f1476c.f1485c;
            if (aVar != null) {
                Exception exc = this.f1479c;
                CoreService.C4029a c4029a = (CoreService.C4029a) aVar;
                Objects.requireNonNull(c4029a);
                exc.toString();
                exc.printStackTrace();
                ServerManager.m4566a(CoreService.this, 2, exc.getMessage());
            }
        }
    }

    public RunnableC1485a(AbstractC1487c abstractC1487c) {
        this.f1476c = abstractC1487c;
    }

    @Override // java.lang.Runnable
    public void run() {
        try {
            AbstractC1487c abstractC1487c = this.f1476c;
            C4823d c4823d = new C4823d();
            Objects.requireNonNull(abstractC1487c);
            c4823d.f12351f = null;
            C4806b c4806b = C4806b.f12286c;
            c4823d.f12348c = new C4806b(this.f1476c.f1484b, true, 0, true, true, 8192, 8192, 8192);
            Objects.requireNonNull(this.f1476c);
            c4823d.f12347b = null;
            AbstractC1487c abstractC1487c2 = this.f1476c;
            c4823d.f12346a = abstractC1487c2.f1483a;
            Objects.requireNonNull(abstractC1487c2);
            c4823d.f12352g = null;
            Objects.requireNonNull(this.f1476c);
            c4823d.f12353h = new AbstractC1487c.b(null);
            c4823d.f12349d = C1409a.f1362a;
            C1488d c1488d = (C1488d) this.f1476c;
            C1412d c1412d = new C1412d(c1488d.f1491f);
            try {
                new C1410b(c1488d.f1491f).m484a(c1412d, c1488d.f1492g);
                if (c4823d.f12350e == null) {
                    c4823d.f12350e = new HashMap();
                }
                c4823d.f12350e.put("*", c1412d);
                c4823d.f12354i = InterfaceC4796d.f12282a;
                abstractC1487c.f1486d = c4823d.m5490a();
                this.f1476c.f1486d.m5489b();
                this.f1476c.f1487e = true;
                C1490b m560a = C1490b.m560a();
                a aVar = new a();
                Objects.requireNonNull(m560a);
                C1490b.f1497b.post(aVar);
                Runtime.getRuntime().addShutdownHook(new b());
            } catch (IllegalAccessException e2) {
                throw new RuntimeException(e2);
            } catch (InstantiationException e3) {
                throw new RuntimeException(e3);
            }
        } catch (Exception e4) {
            C1490b m560a2 = C1490b.m560a();
            c cVar = new c(e4);
            Objects.requireNonNull(m560a2);
            C1490b.f1497b.post(cVar);
        }
    }
}
