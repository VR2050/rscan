package p474l;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: l.y */
/* loaded from: classes3.dex */
public final class C4763y extends C4738b {

    /* renamed from: l */
    public final Socket f12180l;

    public C4763y(@NotNull Socket socket) {
        Intrinsics.checkNotNullParameter(socket, "socket");
        this.f12180l = socket;
    }

    @Override // p474l.C4738b
    @NotNull
    /* renamed from: j */
    public IOException mo5205j(@Nullable IOException iOException) {
        SocketTimeoutException socketTimeoutException = new SocketTimeoutException("timeout");
        if (iOException != null) {
            socketTimeoutException.initCause(iOException);
        }
        return socketTimeoutException;
    }

    @Override // p474l.C4738b
    /* renamed from: k */
    public void mo5125k() {
        try {
            this.f12180l.close();
        } catch (AssertionError e2) {
            if (!C2354n.m2399I0(e2)) {
                throw e2;
            }
            Logger logger = C4754p.f12154a;
            Level level = Level.WARNING;
            StringBuilder m586H = C1499a.m586H("Failed to close timed out socket ");
            m586H.append(this.f12180l);
            logger.log(level, m586H.toString(), (Throwable) e2);
        } catch (Exception e3) {
            Logger logger2 = C4754p.f12154a;
            Level level2 = Level.WARNING;
            StringBuilder m586H2 = C1499a.m586H("Failed to close timed out socket ");
            m586H2.append(this.f12180l);
            logger2.log(level2, m586H2.toString(), (Throwable) e3);
        }
    }
}
