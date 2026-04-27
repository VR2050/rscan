package J2;

import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public final class n extends IOException {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final b f1688b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(b bVar) {
        super("stream was reset: " + bVar);
        t2.j.f(bVar, "errorCode");
        this.f1688b = bVar;
    }
}
