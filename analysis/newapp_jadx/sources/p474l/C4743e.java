package p474l;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.e */
/* loaded from: classes3.dex */
public final class C4743e implements InterfaceC4762x {
    @Override // p474l.InterfaceC4762x
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5151c() {
        return C4737a0.f12115a;
    }

    @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @Override // p474l.InterfaceC4762x, java.io.Flushable
    public void flush() {
    }

    @Override // p474l.InterfaceC4762x
    /* renamed from: x */
    public void mo4923x(@NotNull C4744f source, long j2) {
        Intrinsics.checkNotNullParameter(source, "source");
        source.skip(j2);
    }
}
