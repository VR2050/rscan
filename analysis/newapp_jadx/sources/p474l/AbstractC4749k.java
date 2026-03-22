package p474l;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.k */
/* loaded from: classes3.dex */
public abstract class AbstractC4749k implements InterfaceC4764z {

    /* renamed from: c */
    @NotNull
    public final InterfaceC4764z f12141c;

    public AbstractC4749k(@NotNull InterfaceC4764z delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.f12141c = delegate;
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(@NotNull C4744f sink, long j2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        return this.f12141c.mo4924J(sink, j2);
    }

    @Override // p474l.InterfaceC4764z
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return this.f12141c.mo5044c();
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f12141c.close();
    }

    @NotNull
    public String toString() {
        return getClass().getSimpleName() + '(' + this.f12141c + ')';
    }
}
