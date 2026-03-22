package p005b.p172h.p173a;

import android.net.Uri;
import android.text.TextUtils;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import p005b.p172h.p173a.C1823l.b;
import p005b.p172h.p173a.p174r.AbstractC1833e;
import p005b.p172h.p173a.p174r.AbstractC1833e.a;

/* renamed from: b.h.a.g */
/* loaded from: classes.dex */
public class C1818g {

    /* renamed from: a */
    public final Object f2788a = new Object();

    /* renamed from: b */
    public final ExecutorService f2789b = Executors.newFixedThreadPool(8);

    /* renamed from: c */
    public final Map<String, C1819h> f2790c = new ConcurrentHashMap();

    /* renamed from: d */
    public final ServerSocket f2791d;

    /* renamed from: e */
    public final int f2792e;

    /* renamed from: f */
    public final Thread f2793f;

    /* renamed from: g */
    public final C1814c f2794g;

    /* renamed from: h */
    public final C1823l f2795h;

    /* renamed from: b.h.a.g$b */
    public final class b implements Runnable {

        /* renamed from: c */
        public final Socket f2796c;

        public b(Socket socket) {
            this.f2796c = socket;
        }

        /* JADX WARN: Removed duplicated region for block: B:22:? A[RETURN, SYNTHETIC] */
        @Override // java.lang.Runnable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void run() {
            /*
                r6 = this;
                b.h.a.g r0 = p005b.p172h.p173a.C1818g.this
                java.net.Socket r1 = r6.f2796c
                java.util.Objects.requireNonNull(r0)
                java.lang.String r2 = "Opened connections: "
                java.io.InputStream r3 = r1.getInputStream()     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                b.h.a.d r3 = p005b.p172h.p173a.C1815d.m1160a(r3)     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                java.lang.String r4 = r3.f2782c     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                java.lang.String r4 = p005b.p172h.p173a.C1826o.m1187b(r4)     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                b.h.a.l r5 = r0.f2795h     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                java.util.Objects.requireNonNull(r5)     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                java.lang.String r5 = "ping"
                boolean r5 = r5.equals(r4)     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                if (r5 == 0) goto L2a
                b.h.a.l r3 = r0.f2795h     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                r3.m1180b(r1)     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                goto L31
            L2a:
                b.h.a.h r4 = r0.m1166a(r4)     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
                r4.m1175c(r3, r1)     // Catch: java.lang.Throwable -> L4a java.io.IOException -> L4c p005b.p172h.p173a.C1825n -> L4e java.net.SocketException -> L8e
            L31:
                r0.m1171f(r1)
                java.lang.StringBuilder r1 = new java.lang.StringBuilder
                r1.<init>()
                r1.append(r2)
                int r0 = r0.m1167b()
                r1.append(r0)
                java.lang.String r0 = r1.toString()
                if (r0 == 0) goto Laa
                goto La7
            L4a:
                r3 = move-exception
                goto L72
            L4c:
                r3 = move-exception
                goto L4f
            L4e:
                r3 = move-exception
            L4f:
                b.h.a.n r4 = new b.h.a.n     // Catch: java.lang.Throwable -> L4a
                java.lang.String r5 = "Error processing request"
                r4.<init>(r5, r3)     // Catch: java.lang.Throwable -> L4a
                r0.m1170e(r4)     // Catch: java.lang.Throwable -> L4a
                r0.m1171f(r1)
                java.lang.StringBuilder r1 = new java.lang.StringBuilder
                r1.<init>()
                r1.append(r2)
                int r0 = r0.m1167b()
                r1.append(r0)
                java.lang.String r0 = r1.toString()
                if (r0 == 0) goto Laa
                goto La7
            L72:
                r0.m1171f(r1)
                java.lang.StringBuilder r1 = new java.lang.StringBuilder
                r1.<init>()
                r1.append(r2)
                int r0 = r0.m1167b()
                r1.append(r0)
                java.lang.String r0 = r1.toString()
                if (r0 == 0) goto L8d
                android.text.TextUtils.isEmpty(r0)
            L8d:
                throw r3
            L8e:
                r0.m1171f(r1)
                java.lang.StringBuilder r1 = new java.lang.StringBuilder
                r1.<init>()
                r1.append(r2)
                int r0 = r0.m1167b()
                r1.append(r0)
                java.lang.String r0 = r1.toString()
                if (r0 == 0) goto Laa
            La7:
                android.text.TextUtils.isEmpty(r0)
            Laa:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p172h.p173a.C1818g.b.run():void");
        }
    }

    /* renamed from: b.h.a.g$c */
    public final class c implements Runnable {

        /* renamed from: c */
        public final CountDownLatch f2798c;

        public c(CountDownLatch countDownLatch) {
            this.f2798c = countDownLatch;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f2798c.countDown();
            C1818g c1818g = C1818g.this;
            Objects.requireNonNull(c1818g);
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    c1818g.f2789b.submit(c1818g.new b(c1818g.f2791d.accept()));
                } catch (IOException e2) {
                    c1818g.m1170e(new C1825n("Error during waiting connection", e2));
                    return;
                }
            }
        }
    }

    public C1818g(C1814c c1814c, a aVar) {
        this.f2794g = c1814c;
        try {
            ServerSocket serverSocket = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
            this.f2791d = serverSocket;
            int localPort = serverSocket.getLocalPort();
            this.f2792e = localPort;
            List<Proxy> list = C1821j.f2813a;
            ProxySelector.setDefault(new C1821j(ProxySelector.getDefault(), "127.0.0.1", localPort));
            CountDownLatch countDownLatch = new CountDownLatch(1);
            Thread thread = new Thread(new c(countDownLatch));
            this.f2793f = thread;
            thread.start();
            countDownLatch.await();
            this.f2795h = new C1823l("127.0.0.1", localPort);
            String str = "Proxy cache server started. Is it alive? " + m1169d();
            if (str != null) {
                TextUtils.isEmpty(str);
            }
        } catch (IOException | InterruptedException e2) {
            this.f2789b.shutdown();
            throw new IllegalStateException("Error starting local proxy server", e2);
        }
    }

    /* renamed from: a */
    public final C1819h m1166a(String str) {
        C1819h c1819h;
        synchronized (this.f2788a) {
            c1819h = this.f2790c.get(str);
            if (c1819h == null) {
                c1819h = new C1819h(str, this.f2794g);
                this.f2790c.put(str, c1819h);
            }
        }
        return c1819h;
    }

    /* renamed from: b */
    public final int m1167b() {
        int i2;
        synchronized (this.f2788a) {
            i2 = 0;
            Iterator<C1819h> it = this.f2790c.values().iterator();
            while (it.hasNext()) {
                i2 += it.next().f2800a.get();
            }
        }
        return i2;
    }

    /* renamed from: c */
    public String m1168c(String str) {
        Objects.requireNonNull(str, "Url can't be null!");
        C1814c c1814c = this.f2794g;
        if (new File(c1814c.f2775a, c1814c.f2776b.m1189a(str)).exists()) {
            C1814c c1814c2 = this.f2794g;
            File file = new File(c1814c2.f2775a, c1814c2.f2776b.m1189a(str));
            try {
                AbstractC1833e abstractC1833e = (AbstractC1833e) this.f2794g.f2777c;
                abstractC1833e.f2836a.submit(abstractC1833e.new a(file));
            } catch (IOException e2) {
                C1817f.m1164a("Error touching file " + file, e2);
            }
            return Uri.fromFile(file).toString();
        }
        if (!m1169d()) {
            return str;
        }
        Locale locale = Locale.US;
        Object[] objArr = new Object[3];
        objArr[0] = "127.0.0.1";
        objArr[1] = Integer.valueOf(this.f2792e);
        try {
            objArr[2] = URLEncoder.encode(str, "utf-8");
            return String.format(locale, "http://%s:%d/%s", objArr);
        } catch (UnsupportedEncodingException e3) {
            throw new RuntimeException("Error encoding url", e3);
        }
    }

    /* renamed from: d */
    public final boolean m1169d() {
        C1823l c1823l = this.f2795h;
        Objects.requireNonNull(c1823l);
        int i2 = 70;
        int i3 = 0;
        while (i3 < 3) {
            try {
            } catch (InterruptedException e2) {
                e = e2;
                C1817f.m1164a("Error pinging server due to unexpected error", e);
            } catch (ExecutionException e3) {
                e = e3;
                C1817f.m1164a("Error pinging server due to unexpected error", e);
            } catch (TimeoutException unused) {
                C1817f.m1165b("HttpProxyCacheDebuger", "Error pinging server (attempt: " + i3 + ", timeout: " + i2 + "). ");
            }
            if (((Boolean) c1823l.f2817a.submit(c1823l.new b(null)).get(i2, TimeUnit.MILLISECONDS)).booleanValue()) {
                return true;
            }
            i3++;
            i2 *= 2;
        }
        Locale locale = Locale.US;
        Object[] objArr = new Object[3];
        objArr[0] = Integer.valueOf(i3);
        objArr[1] = Integer.valueOf(i2 / 2);
        try {
            objArr[2] = ProxySelector.getDefault().select(new URI(c1823l.m1179a()));
            String format = String.format(locale, "Error pinging server (attempts: %d, max timeout: %d). If you see this message, please, report at https://github.com/danikula/AndroidVideoCache/issues/134. Default proxies are: %s", objArr);
            C1817f.m1164a(format, new C1825n(format));
            return false;
        } catch (URISyntaxException e4) {
            throw new IllegalStateException(e4);
        }
    }

    /* renamed from: e */
    public final void m1170e(Throwable th) {
        TextUtils.isEmpty(th.getMessage());
    }

    /* renamed from: f */
    public final void m1171f(Socket socket) {
        try {
            if (!socket.isInputShutdown()) {
                socket.shutdownInput();
            }
        } catch (SocketException | IOException unused) {
        }
        try {
            if (!socket.isOutputShutdown()) {
                socket.shutdownOutput();
            }
        } catch (IOException e2) {
            C1817f.m1165b("Failed to close socket on proxy side: {}. It seems client have already closed connection.", e2.getMessage());
        }
        try {
            if (socket.isClosed()) {
                return;
            }
            socket.close();
        } catch (IOException unused2) {
        }
    }

    /* renamed from: g */
    public void m1172g(InterfaceC1813b interfaceC1813b) {
        synchronized (this.f2788a) {
            Iterator<C1819h> it = this.f2790c.values().iterator();
            while (it.hasNext()) {
                it.next().f2803d.remove(interfaceC1813b);
            }
        }
    }
}
