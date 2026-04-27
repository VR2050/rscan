package M2;

import M2.l;
import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.conscrypt.Conscrypt;

/* JADX INFO: loaded from: classes.dex */
public final class k implements m {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final b f1831b = new b(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final l.a f1830a = new a();

    public static final class a implements l.a {
        a() {
        }

        @Override // M2.l.a
        public boolean a(SSLSocket sSLSocket) {
            t2.j.f(sSLSocket, "sslSocket");
            return L2.d.f1727f.c() && Conscrypt.isConscrypt(sSLSocket);
        }

        @Override // M2.l.a
        public m b(SSLSocket sSLSocket) {
            t2.j.f(sSLSocket, "sslSocket");
            return new k();
        }
    }

    public static final class b {
        private b() {
        }

        public final l.a a() {
            return k.f1830a;
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    @Override // M2.m
    public boolean a(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        return Conscrypt.isConscrypt(sSLSocket);
    }

    @Override // M2.m
    public boolean b() {
        return L2.d.f1727f.c();
    }

    @Override // M2.m
    public String c(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        if (a(sSLSocket)) {
            return Conscrypt.getApplicationProtocol(sSLSocket);
        }
        return null;
    }

    @Override // M2.m
    public void d(SSLSocket sSLSocket, String str, List list) {
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
        if (a(sSLSocket)) {
            Conscrypt.setUseSessionTickets(sSLSocket, true);
            Object[] array = L2.j.f1746c.b(list).toArray(new String[0]);
            if (array == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            Conscrypt.setApplicationProtocols(sSLSocket, (String[]) array);
        }
    }
}
