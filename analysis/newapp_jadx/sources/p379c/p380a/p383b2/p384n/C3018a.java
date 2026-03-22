package p379c.p380a.p383b2.p384n;

import java.util.concurrent.CancellationException;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.a */
/* loaded from: classes2.dex */
public final class C3018a extends CancellationException {

    /* renamed from: c */
    @NotNull
    public final InterfaceC3007c<?> f8266c;

    public C3018a(@NotNull InterfaceC3007c<?> interfaceC3007c) {
        super("Flow was aborted, no more elements needed");
        this.f8266c = interfaceC3007c;
    }

    @Override // java.lang.Throwable
    @NotNull
    public Throwable fillInStackTrace() {
        setStackTrace(new StackTraceElement[0]);
        return this;
    }
}
