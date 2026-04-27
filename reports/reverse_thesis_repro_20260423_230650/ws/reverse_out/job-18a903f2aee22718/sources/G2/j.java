package G2;

import h2.AbstractC0555a;
import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public final class j extends RuntimeException {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private IOException f962b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final IOException f963c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(IOException iOException) {
        super(iOException);
        t2.j.f(iOException, "firstConnectException");
        this.f963c = iOException;
        this.f962b = iOException;
    }

    public final void a(IOException iOException) {
        t2.j.f(iOException, "e");
        AbstractC0555a.a(this.f963c, iOException);
        this.f962b = iOException;
    }

    public final IOException b() {
        return this.f963c;
    }

    public final IOException c() {
        return this.f962b;
    }
}
