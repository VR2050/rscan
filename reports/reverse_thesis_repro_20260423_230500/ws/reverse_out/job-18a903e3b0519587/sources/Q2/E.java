package Q2;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.logging.Level;

/* JADX INFO: loaded from: classes.dex */
final class E extends C0211g {

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final Socket f2521m;

    public E(Socket socket) {
        t2.j.f(socket, "socket");
        this.f2521m = socket;
    }

    @Override // Q2.C0211g
    protected IOException t(IOException iOException) {
        SocketTimeoutException socketTimeoutException = new SocketTimeoutException("timeout");
        if (iOException != null) {
            socketTimeoutException.initCause(iOException);
        }
        return socketTimeoutException;
    }

    @Override // Q2.C0211g
    protected void x() {
        try {
            this.f2521m.close();
        } catch (AssertionError e3) {
            if (!t.e(e3)) {
                throw e3;
            }
            u.f2577a.log(Level.WARNING, "Failed to close timed out socket " + this.f2521m, (Throwable) e3);
        } catch (Exception e4) {
            u.f2577a.log(Level.WARNING, "Failed to close timed out socket " + this.f2521m, (Throwable) e4);
        }
    }
}
