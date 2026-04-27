package G2;

import B2.l;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ProtocolException;
import java.net.UnknownServiceException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f874a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f875b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f876c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f877d;

    public b(List list) {
        t2.j.f(list, "connectionSpecs");
        this.f877d = list;
    }

    private final boolean c(SSLSocket sSLSocket) {
        int size = this.f877d.size();
        for (int i3 = this.f874a; i3 < size; i3++) {
            if (((l) this.f877d.get(i3)).e(sSLSocket)) {
                return true;
            }
        }
        return false;
    }

    public final l a(SSLSocket sSLSocket) throws UnknownServiceException, CloneNotSupportedException {
        l lVar;
        t2.j.f(sSLSocket, "sslSocket");
        int i3 = this.f874a;
        int size = this.f877d.size();
        while (true) {
            if (i3 >= size) {
                lVar = null;
                break;
            }
            lVar = (l) this.f877d.get(i3);
            if (lVar.e(sSLSocket)) {
                this.f874a = i3 + 1;
                break;
            }
            i3++;
        }
        if (lVar != null) {
            this.f875b = c(sSLSocket);
            lVar.c(sSLSocket, this.f876c);
            return lVar;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Unable to find acceptable protocols. isFallback=");
        sb.append(this.f876c);
        sb.append(',');
        sb.append(" modes=");
        sb.append(this.f877d);
        sb.append(',');
        sb.append(" supported protocols=");
        String[] enabledProtocols = sSLSocket.getEnabledProtocols();
        t2.j.c(enabledProtocols);
        String string = Arrays.toString(enabledProtocols);
        t2.j.e(string, "java.util.Arrays.toString(this)");
        sb.append(string);
        throw new UnknownServiceException(sb.toString());
    }

    public final boolean b(IOException iOException) {
        t2.j.f(iOException, "e");
        this.f876c = true;
        return (!this.f875b || (iOException instanceof ProtocolException) || (iOException instanceof InterruptedIOException) || ((iOException instanceof SSLHandshakeException) && (iOException.getCause() instanceof CertificateException)) || (iOException instanceof SSLPeerUnverifiedException) || !(iOException instanceof SSLException)) ? false : true;
    }
}
