package L2;

import M2.k;
import M2.l;
import M2.m;
import M2.n;
import android.os.Build;
import android.security.NetworkSecurityPolicy;
import i2.AbstractC0586n;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class b extends j {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final boolean f1717f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final a f1718g = new a(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f1719d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final M2.j f1720e;

    public static final class a {
        private a() {
        }

        public final j a() {
            if (b()) {
                return new b();
            }
            return null;
        }

        public final boolean b() {
            return b.f1717f;
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX INFO: renamed from: L2.b$b, reason: collision with other inner class name */
    public static final class C0028b implements O2.e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final X509TrustManager f1721a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Method f1722b;

        public C0028b(X509TrustManager x509TrustManager, Method method) {
            t2.j.f(x509TrustManager, "trustManager");
            t2.j.f(method, "findByIssuerAndSignatureMethod");
            this.f1721a = x509TrustManager;
            this.f1722b = method;
        }

        @Override // O2.e
        public X509Certificate a(X509Certificate x509Certificate) {
            t2.j.f(x509Certificate, "cert");
            try {
                Object objInvoke = this.f1722b.invoke(this.f1721a, x509Certificate);
                if (objInvoke != null) {
                    return ((TrustAnchor) objInvoke).getTrustedCert();
                }
                throw new NullPointerException("null cannot be cast to non-null type java.security.cert.TrustAnchor");
            } catch (IllegalAccessException e3) {
                throw new AssertionError("unable to get issues and signature", e3);
            } catch (InvocationTargetException unused) {
                return null;
            }
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof C0028b)) {
                return false;
            }
            C0028b c0028b = (C0028b) obj;
            return t2.j.b(this.f1721a, c0028b.f1721a) && t2.j.b(this.f1722b, c0028b.f1722b);
        }

        public int hashCode() {
            X509TrustManager x509TrustManager = this.f1721a;
            int iHashCode = (x509TrustManager != null ? x509TrustManager.hashCode() : 0) * 31;
            Method method = this.f1722b;
            return iHashCode + (method != null ? method.hashCode() : 0);
        }

        public String toString() {
            return "CustomTrustRootIndex(trustManager=" + this.f1721a + ", findByIssuerAndSignatureMethod=" + this.f1722b + ")";
        }
    }

    static {
        boolean z3 = false;
        if (j.f1746c.h() && Build.VERSION.SDK_INT < 30) {
            z3 = true;
        }
        f1717f = z3;
    }

    public b() {
        List listJ = AbstractC0586n.j(n.a.b(n.f1834j, null, 1, null), new l(M2.h.f1817g.d()), new l(k.f1831b.a()), new l(M2.i.f1825b.a()));
        ArrayList arrayList = new ArrayList();
        for (Object obj : listJ) {
            if (((m) obj).b()) {
                arrayList.add(obj);
            }
        }
        this.f1719d = arrayList;
        this.f1720e = M2.j.f1826d.a();
    }

    @Override // L2.j
    public O2.c c(X509TrustManager x509TrustManager) {
        t2.j.f(x509TrustManager, "trustManager");
        M2.d dVarA = M2.d.f1809d.a(x509TrustManager);
        return dVarA != null ? dVarA : super.c(x509TrustManager);
    }

    @Override // L2.j
    public O2.e d(X509TrustManager x509TrustManager) {
        t2.j.f(x509TrustManager, "trustManager");
        try {
            Method declaredMethod = x509TrustManager.getClass().getDeclaredMethod("findTrustAnchorByIssuerAndSignature", X509Certificate.class);
            t2.j.e(declaredMethod, "method");
            declaredMethod.setAccessible(true);
            return new C0028b(x509TrustManager, declaredMethod);
        } catch (NoSuchMethodException unused) {
            return super.d(x509TrustManager);
        }
    }

    @Override // L2.j
    public void e(SSLSocket sSLSocket, String str, List list) {
        Object next;
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
        Iterator it = this.f1719d.iterator();
        while (true) {
            if (!it.hasNext()) {
                next = null;
                break;
            } else {
                next = it.next();
                if (((m) next).a(sSLSocket)) {
                    break;
                }
            }
        }
        m mVar = (m) next;
        if (mVar != null) {
            mVar.d(sSLSocket, str, list);
        }
    }

    @Override // L2.j
    public void f(Socket socket, InetSocketAddress inetSocketAddress, int i3) throws IOException {
        t2.j.f(socket, "socket");
        t2.j.f(inetSocketAddress, "address");
        try {
            socket.connect(inetSocketAddress, i3);
        } catch (ClassCastException e3) {
            if (Build.VERSION.SDK_INT != 26) {
                throw e3;
            }
            throw new IOException("Exception in connect", e3);
        }
    }

    @Override // L2.j
    public String h(SSLSocket sSLSocket) {
        Object next;
        t2.j.f(sSLSocket, "sslSocket");
        Iterator it = this.f1719d.iterator();
        while (true) {
            if (!it.hasNext()) {
                next = null;
                break;
            }
            next = it.next();
            if (((m) next).a(sSLSocket)) {
                break;
            }
        }
        m mVar = (m) next;
        if (mVar != null) {
            return mVar.c(sSLSocket);
        }
        return null;
    }

    @Override // L2.j
    public Object i(String str) {
        t2.j.f(str, "closer");
        return this.f1720e.a(str);
    }

    @Override // L2.j
    public boolean j(String str) {
        t2.j.f(str, "hostname");
        return NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(str);
    }

    @Override // L2.j
    public void m(String str, Object obj) {
        t2.j.f(str, "message");
        if (this.f1720e.b(obj)) {
            return;
        }
        j.l(this, str, 5, null, 4, null);
    }
}
