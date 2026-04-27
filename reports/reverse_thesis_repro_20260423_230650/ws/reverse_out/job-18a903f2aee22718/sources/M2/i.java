package M2;

import M2.l;
import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/* JADX INFO: loaded from: classes.dex */
public final class i implements m {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final b f1825b = new b(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final l.a f1824a = new a();

    public static final class a implements l.a {
        a() {
        }

        @Override // M2.l.a
        public boolean a(SSLSocket sSLSocket) {
            t2.j.f(sSLSocket, "sslSocket");
            L2.c.f1724f.b();
            return false;
        }

        @Override // M2.l.a
        public m b(SSLSocket sSLSocket) {
            t2.j.f(sSLSocket, "sslSocket");
            return new i();
        }
    }

    public static final class b {
        private b() {
        }

        public final l.a a() {
            return i.f1824a;
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    @Override // M2.m
    public boolean a(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        return false;
    }

    @Override // M2.m
    public boolean b() {
        return L2.c.f1724f.b();
    }

    @Override // M2.m
    public String c(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        String applicationProtocol = ((BCSSLSocket) sSLSocket).getApplicationProtocol();
        if (applicationProtocol == null || (applicationProtocol.hashCode() == 0 && applicationProtocol.equals(""))) {
            return null;
        }
        return applicationProtocol;
    }

    @Override // M2.m
    public void d(SSLSocket sSLSocket, String str, List list) {
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
        if (a(sSLSocket)) {
            BCSSLSocket bCSSLSocket = (BCSSLSocket) sSLSocket;
            BCSSLParameters parameters = bCSSLSocket.getParameters();
            t2.j.e(parameters, "sslParameters");
            Object[] array = L2.j.f1746c.b(list).toArray(new String[0]);
            if (array == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            parameters.setApplicationProtocols((String[]) array);
            bCSSLSocket.setParameters(parameters);
        }
    }
}
