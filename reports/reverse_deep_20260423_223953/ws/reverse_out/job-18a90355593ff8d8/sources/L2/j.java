package L2;

import B2.A;
import B2.z;
import i2.AbstractC0586n;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class j {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static volatile j f1744a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Logger f1745b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f1746c;

    public static final class a {
        private a() {
        }

        private final j d() {
            M2.e.f1814c.b();
            j jVarA = L2.a.f1715f.a();
            if (jVarA != null) {
                return jVarA;
            }
            j jVarA2 = b.f1718g.a();
            t2.j.c(jVarA2);
            return jVarA2;
        }

        private final j e() {
            i iVarA;
            c cVarA;
            d dVarB;
            if (j() && (dVarB = d.f1727f.b()) != null) {
                return dVarB;
            }
            if (i() && (cVarA = c.f1724f.a()) != null) {
                return cVarA;
            }
            if (k() && (iVarA = i.f1742f.a()) != null) {
                return iVarA;
            }
            h hVarA = h.f1740e.a();
            if (hVarA != null) {
                return hVarA;
            }
            j jVarA = e.f1730i.a();
            return jVarA != null ? jVarA : new j();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final j f() {
            return h() ? d() : e();
        }

        private final boolean i() {
            Provider provider = Security.getProviders()[0];
            t2.j.e(provider, "Security.getProviders()[0]");
            return t2.j.b("BC", provider.getName());
        }

        private final boolean j() {
            Provider provider = Security.getProviders()[0];
            t2.j.e(provider, "Security.getProviders()[0]");
            return t2.j.b("Conscrypt", provider.getName());
        }

        private final boolean k() {
            Provider provider = Security.getProviders()[0];
            t2.j.e(provider, "Security.getProviders()[0]");
            return t2.j.b("OpenJSSE", provider.getName());
        }

        public final List b(List list) {
            t2.j.f(list, "protocols");
            ArrayList arrayList = new ArrayList();
            for (Object obj : list) {
                if (((A) obj) != A.HTTP_1_0) {
                    arrayList.add(obj);
                }
            }
            ArrayList arrayList2 = new ArrayList(AbstractC0586n.o(arrayList, 10));
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                arrayList2.add(((A) it.next()).toString());
            }
            return arrayList2;
        }

        public final byte[] c(List list) {
            t2.j.f(list, "protocols");
            Q2.i iVar = new Q2.i();
            for (String str : b(list)) {
                iVar.L(str.length());
                iVar.j0(str);
            }
            return iVar.I();
        }

        public final j g() {
            return j.f1744a;
        }

        public final boolean h() {
            return t2.j.b("Dalvik", System.getProperty("java.vm.name"));
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static {
        a aVar = new a(null);
        f1746c = aVar;
        f1744a = aVar.f();
        f1745b = Logger.getLogger(z.class.getName());
    }

    public static /* synthetic */ void l(j jVar, String str, int i3, Throwable th, int i4, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: log");
        }
        if ((i4 & 2) != 0) {
            i3 = 4;
        }
        if ((i4 & 4) != 0) {
            th = null;
        }
        jVar.k(str, i3, th);
    }

    public void b(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
    }

    public O2.c c(X509TrustManager x509TrustManager) {
        t2.j.f(x509TrustManager, "trustManager");
        return new O2.a(d(x509TrustManager));
    }

    public O2.e d(X509TrustManager x509TrustManager) {
        t2.j.f(x509TrustManager, "trustManager");
        X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();
        t2.j.e(acceptedIssuers, "trustManager.acceptedIssuers");
        return new O2.b((X509Certificate[]) Arrays.copyOf(acceptedIssuers, acceptedIssuers.length));
    }

    public void e(SSLSocket sSLSocket, String str, List list) {
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
    }

    public void f(Socket socket, InetSocketAddress inetSocketAddress, int i3) throws IOException {
        t2.j.f(socket, "socket");
        t2.j.f(inetSocketAddress, "address");
        socket.connect(inetSocketAddress, i3);
    }

    public final String g() {
        return "OkHttp";
    }

    public String h(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        return null;
    }

    public Object i(String str) {
        t2.j.f(str, "closer");
        if (f1745b.isLoggable(Level.FINE)) {
            return new Throwable(str);
        }
        return null;
    }

    public boolean j(String str) {
        t2.j.f(str, "hostname");
        return true;
    }

    public void k(String str, int i3, Throwable th) {
        t2.j.f(str, "message");
        f1745b.log(i3 == 5 ? Level.WARNING : Level.INFO, str, th);
    }

    public void m(String str, Object obj) {
        t2.j.f(str, "message");
        if (obj == null) {
            str = str + " To see where this was allocated, set the OkHttpClient logger level to FINE: Logger.getLogger(OkHttpClient.class.getName()).setLevel(Level.FINE);";
        }
        k(str, 5, (Throwable) obj);
    }

    public SSLContext n() throws NoSuchAlgorithmException {
        SSLContext sSLContext = SSLContext.getInstance("TLS");
        t2.j.e(sSLContext, "SSLContext.getInstance(\"TLS\")");
        return sSLContext;
    }

    public SSLSocketFactory o(X509TrustManager x509TrustManager) {
        t2.j.f(x509TrustManager, "trustManager");
        try {
            SSLContext sSLContextN = n();
            sSLContextN.init(null, new TrustManager[]{x509TrustManager}, null);
            SSLSocketFactory socketFactory = sSLContextN.getSocketFactory();
            t2.j.e(socketFactory, "newSSLContext().apply {\n…ll)\n      }.socketFactory");
            return socketFactory;
        } catch (GeneralSecurityException e3) {
            throw new AssertionError("No System TLS: " + e3, e3);
        }
    }

    public X509TrustManager p() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);
        t2.j.e(trustManagerFactory, "factory");
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        t2.j.c(trustManagers);
        if (trustManagers.length == 1 && (trustManagers[0] instanceof X509TrustManager)) {
            TrustManager trustManager = trustManagers[0];
            if (trustManager != null) {
                return (X509TrustManager) trustManager;
            }
            throw new NullPointerException("null cannot be cast to non-null type javax.net.ssl.X509TrustManager");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Unexpected default trust managers: ");
        String string = Arrays.toString(trustManagers);
        t2.j.e(string, "java.util.Arrays.toString(this)");
        sb.append(string);
        throw new IllegalStateException(sb.toString().toString());
    }

    public String toString() {
        String simpleName = getClass().getSimpleName();
        t2.j.e(simpleName, "javaClass.simpleName");
        return simpleName;
    }
}
