package M2;

import java.util.List;
import javax.net.ssl.SSLSocket;

/* JADX INFO: loaded from: classes.dex */
public final class l implements m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private m f1832a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final a f1833b;

    public interface a {
        boolean a(SSLSocket sSLSocket);

        m b(SSLSocket sSLSocket);
    }

    public l(a aVar) {
        t2.j.f(aVar, "socketAdapterFactory");
        this.f1833b = aVar;
    }

    private final synchronized m e(SSLSocket sSLSocket) {
        try {
            if (this.f1832a == null && this.f1833b.a(sSLSocket)) {
                this.f1832a = this.f1833b.b(sSLSocket);
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.f1832a;
    }

    @Override // M2.m
    public boolean a(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        return this.f1833b.a(sSLSocket);
    }

    @Override // M2.m
    public boolean b() {
        return true;
    }

    @Override // M2.m
    public String c(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        m mVarE = e(sSLSocket);
        if (mVarE != null) {
            return mVarE.c(sSLSocket);
        }
        return null;
    }

    @Override // M2.m
    public void d(SSLSocket sSLSocket, String str, List list) {
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
        m mVarE = e(sSLSocket);
        if (mVarE != null) {
            mVarE.d(sSLSocket, str, list);
        }
    }
}
