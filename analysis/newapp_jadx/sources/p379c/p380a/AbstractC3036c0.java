package p379c.p380a;

import java.util.Objects;
import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.ExperimentalStdlibApi;
import kotlin.coroutines.AbstractCoroutineContextElement;
import kotlin.coroutines.AbstractCoroutineContextKey;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.ContinuationInterceptor;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2957f;

/* renamed from: c.a.c0 */
/* loaded from: classes2.dex */
public abstract class AbstractC3036c0 extends AbstractCoroutineContextElement implements ContinuationInterceptor {
    public static final a Key = new a(null);

    @ExperimentalStdlibApi
    /* renamed from: c.a.c0$a */
    public static final class a extends AbstractCoroutineContextKey<ContinuationInterceptor, AbstractC3036c0> {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
            super(ContinuationInterceptor.INSTANCE, C3003b0.f8192c);
        }
    }

    public AbstractC3036c0() {
        super(ContinuationInterceptor.INSTANCE);
    }

    public abstract void dispatch(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable);

    public void dispatchYield(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        dispatch(coroutineContext, runnable);
    }

    @Override // kotlin.coroutines.AbstractCoroutineContextElement, kotlin.coroutines.CoroutineContext.Element, kotlin.coroutines.CoroutineContext
    @Nullable
    public <E extends CoroutineContext.Element> E get(@NotNull CoroutineContext.Key<E> key) {
        return (E) ContinuationInterceptor.DefaultImpls.get(this, key);
    }

    @Override // kotlin.coroutines.ContinuationInterceptor
    @NotNull
    public final <T> Continuation<T> interceptContinuation(@NotNull Continuation<? super T> continuation) {
        return new C2957f(this, continuation);
    }

    public boolean isDispatchNeeded(@NotNull CoroutineContext coroutineContext) {
        return true;
    }

    @Override // kotlin.coroutines.AbstractCoroutineContextElement, kotlin.coroutines.CoroutineContext.Element, kotlin.coroutines.CoroutineContext
    @NotNull
    public CoroutineContext minusKey(@NotNull CoroutineContext.Key<?> key) {
        return ContinuationInterceptor.DefaultImpls.minusKey(this, key);
    }

    @Deprecated(level = DeprecationLevel.ERROR, message = "Operator '+' on two CoroutineDispatcher objects is meaningless. CoroutineDispatcher is a coroutine context element and `+` is a set-sum operator for coroutine contexts. The dispatcher to the right of `+` just replaces the dispatcher to the left.")
    @NotNull
    public final AbstractC3036c0 plus(@NotNull AbstractC3036c0 abstractC3036c0) {
        return abstractC3036c0;
    }

    @Override // kotlin.coroutines.ContinuationInterceptor
    public void releaseInterceptedContinuation(@NotNull Continuation<?> continuation) {
        Objects.requireNonNull(continuation, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<*>");
        Object obj = ((C2957f) continuation)._reusableCancellableContinuation;
        if (!(obj instanceof C3069j)) {
            obj = null;
        }
        C3069j c3069j = (C3069j) obj;
        if (c3069j != null) {
            c3069j.m3609p();
        }
    }

    @NotNull
    public String toString() {
        return getClass().getSimpleName() + '@' + C2354n.m2495m0(this);
    }
}
