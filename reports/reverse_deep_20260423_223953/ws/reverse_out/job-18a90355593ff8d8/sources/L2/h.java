package L2;

import java.util.List;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class h extends j {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final boolean f1739d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f1740e = new a(0 == true ? 1 : 0);

    public static final class a {
        private a() {
        }

        public final h a() {
            if (b()) {
                return new h();
            }
            return null;
        }

        public final boolean b() {
            return h.f1739d;
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    static {
        String property = System.getProperty("java.specification.version");
        Integer numF = property != null ? z2.g.f(property) : null;
        boolean z3 = true;
        if (numF == null) {
            try {
                SSLSocket.class.getMethod("getApplicationProtocol", new Class[0]);
            } catch (NoSuchMethodException unused) {
                z3 = false;
            }
        } else if (numF.intValue() < 9) {
            z3 = false;
        }
        f1739d = z3;
    }

    @Override // L2.j
    public void e(SSLSocket sSLSocket, String str, List list) {
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
        SSLParameters sSLParameters = sSLSocket.getSSLParameters();
        List listB = j.f1746c.b(list);
        t2.j.e(sSLParameters, "sslParameters");
        Object[] array = listB.toArray(new String[0]);
        if (array == null) {
            throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
        }
        sSLParameters.setApplicationProtocols((String[]) array);
        sSLSocket.setSSLParameters(sSLParameters);
    }

    @Override // L2.j
    public String h(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        try {
            String applicationProtocol = sSLSocket.getApplicationProtocol();
            if (applicationProtocol == null) {
                return null;
            }
            if (applicationProtocol.hashCode() == 0) {
                if (applicationProtocol.equals("")) {
                    return null;
                }
            }
            return applicationProtocol;
        } catch (UnsupportedOperationException unused) {
            return null;
        }
    }
}
