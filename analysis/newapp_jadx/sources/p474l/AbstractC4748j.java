package p474l;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.j */
/* loaded from: classes3.dex */
public abstract class AbstractC4748j implements InterfaceC4762x {

    /* renamed from: c */
    @NotNull
    public final InterfaceC4762x f12140c;

    public AbstractC4748j(@NotNull InterfaceC4762x delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.f12140c = delegate;
    }

    @Override // p474l.InterfaceC4762x
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5151c() {
        return this.f12140c.mo5151c();
    }

    @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f12140c.close();
    }

    @Override // p474l.InterfaceC4762x, java.io.Flushable
    public void flush() {
        this.f12140c.flush();
    }

    @NotNull
    public String toString() {
        return getClass().getSimpleName() + '(' + this.f12140c + ')';
    }

    @Override // p474l.InterfaceC4762x
    /* renamed from: x */
    public void mo4923x(@NotNull C4744f source, long j2) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.f12140c.mo4923x(source, j2);
    }
}
