package p379c.p380a.p383b2.p384n;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.jvm.internal.CoroutineStackFrame;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.b2.n.p */
/* loaded from: classes2.dex */
public final class C3033p<T> implements Continuation<T>, CoroutineStackFrame {

    /* renamed from: c */
    public final Continuation<T> f8334c;

    /* renamed from: e */
    @NotNull
    public final CoroutineContext f8335e;

    /* JADX WARN: Multi-variable type inference failed */
    public C3033p(@NotNull Continuation<? super T> continuation, @NotNull CoroutineContext coroutineContext) {
        this.f8334c = continuation;
        this.f8335e = coroutineContext;
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public CoroutineStackFrame getCallerFrame() {
        Continuation<T> continuation = this.f8334c;
        if (!(continuation instanceof CoroutineStackFrame)) {
            continuation = null;
        }
        return (CoroutineStackFrame) continuation;
    }

    @Override // kotlin.coroutines.Continuation
    @NotNull
    public CoroutineContext getContext() {
        return this.f8335e;
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public StackTraceElement getStackTraceElement() {
        return null;
    }

    @Override // kotlin.coroutines.Continuation
    public void resumeWith(@NotNull Object obj) {
        this.f8334c.resumeWith(obj);
    }
}
