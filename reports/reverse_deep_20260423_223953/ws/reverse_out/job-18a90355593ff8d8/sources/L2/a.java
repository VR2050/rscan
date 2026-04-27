package L2;

import M2.k;
import M2.l;
import M2.m;
import android.os.Build;
import android.security.NetworkSecurityPolicy;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class a extends j {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final boolean f1714e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final C0027a f1715f = new C0027a(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f1716d;

    /* JADX INFO: renamed from: L2.a$a, reason: collision with other inner class name */
    public static final class C0027a {
        private C0027a() {
        }

        public final j a() {
            if (b()) {
                return new a();
            }
            return null;
        }

        public final boolean b() {
            return a.f1714e;
        }

        public /* synthetic */ C0027a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static {
        f1714e = j.f1746c.h() && Build.VERSION.SDK_INT >= 29;
    }

    public a() {
        List listJ = AbstractC0586n.j(M2.c.f1808a.a(), new l(M2.h.f1817g.d()), new l(k.f1831b.a()), new l(M2.i.f1825b.a()));
        ArrayList arrayList = new ArrayList();
        for (Object obj : listJ) {
            if (((m) obj).b()) {
                arrayList.add(obj);
            }
        }
        this.f1716d = arrayList;
    }

    @Override // L2.j
    public O2.c c(X509TrustManager x509TrustManager) {
        t2.j.f(x509TrustManager, "trustManager");
        M2.d dVarA = M2.d.f1809d.a(x509TrustManager);
        return dVarA != null ? dVarA : super.c(x509TrustManager);
    }

    @Override // L2.j
    public void e(SSLSocket sSLSocket, String str, List list) {
        Object next;
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
        Iterator it = this.f1716d.iterator();
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
    public String h(SSLSocket sSLSocket) {
        Object next;
        t2.j.f(sSLSocket, "sslSocket");
        Iterator it = this.f1716d.iterator();
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
    public boolean j(String str) {
        t2.j.f(str, "hostname");
        return NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(str);
    }
}
