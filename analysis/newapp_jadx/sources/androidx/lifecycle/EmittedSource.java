package androidx.lifecycle;

import androidx.annotation.MainThread;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3036c0;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3082n0;
import p379c.p380a.p381a.C2964m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\b\u0000\u0018\u00002\u00020\u0001B\u001f\u0012\n\u0010\t\u001a\u0006\u0012\u0002\b\u00030\b\u0012\n\u0010\f\u001a\u0006\u0012\u0002\b\u00030\u000b¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0003\u001a\u00020\u0002H\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0013\u0010\u0005\u001a\u00020\u0002H\u0086@ø\u0001\u0000¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0007\u0010\u0004R\u001a\u0010\t\u001a\u0006\u0012\u0002\b\u00030\b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\t\u0010\nR\u001a\u0010\f\u001a\u0006\u0012\u0002\b\u00030\u000b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\f\u0010\rR\u0016\u0010\u000f\u001a\u00020\u000e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000f\u0010\u0010\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0013"}, m5311d2 = {"Landroidx/lifecycle/EmittedSource;", "Lc/a/n0;", "", "removeSource", "()V", "disposeNow", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "dispose", "Landroidx/lifecycle/LiveData;", "source", "Landroidx/lifecycle/LiveData;", "Landroidx/lifecycle/MediatorLiveData;", "mediator", "Landroidx/lifecycle/MediatorLiveData;", "", "disposed", "Z", "<init>", "(Landroidx/lifecycle/LiveData;Landroidx/lifecycle/MediatorLiveData;)V", "lifecycle-livedata-ktx_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class EmittedSource implements InterfaceC3082n0 {
    private boolean disposed;
    private final MediatorLiveData<?> mediator;
    private final LiveData<?> source;

    public EmittedSource(@NotNull LiveData<?> source, @NotNull MediatorLiveData<?> mediator) {
        Intrinsics.checkParameterIsNotNull(source, "source");
        Intrinsics.checkParameterIsNotNull(mediator, "mediator");
        this.source = source;
        this.mediator = mediator;
    }

    /* JADX INFO: Access modifiers changed from: private */
    @MainThread
    public final void removeSource() {
        if (this.disposed) {
            return;
        }
        this.mediator.removeSource(this.source);
        this.disposed = true;
    }

    @Override // p379c.p380a.InterfaceC3082n0
    public void dispose() {
        AbstractC3036c0 abstractC3036c0 = C3079m0.f8430a;
        C2354n.m2435U0(C2354n.m2456b(C2964m.f8127b.mo3620U()), null, 0, new EmittedSource$dispose$1(this, null), 3, null);
    }

    @Nullable
    public final Object disposeNow(@NotNull Continuation<? super Unit> continuation) {
        AbstractC3036c0 abstractC3036c0 = C3079m0.f8430a;
        return C2354n.m2471e2(C2964m.f8127b.mo3620U(), new EmittedSource$disposeNow$2(this, null), continuation);
    }
}
