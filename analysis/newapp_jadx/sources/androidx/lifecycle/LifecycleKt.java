package androidx.lifecycle;

import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.AbstractC3036c0;
import p379c.p380a.C3079m0;
import p379c.p380a.C3101t1;
import p379c.p380a.p381a.C2964m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\"\u0017\u0010\u0004\u001a\u00020\u0001*\u00020\u00008F@\u0006¢\u0006\u0006\u001a\u0004\b\u0002\u0010\u0003¨\u0006\u0005"}, m5311d2 = {"Landroidx/lifecycle/Lifecycle;", "Landroidx/lifecycle/LifecycleCoroutineScope;", "getCoroutineScope", "(Landroidx/lifecycle/Lifecycle;)Landroidx/lifecycle/LifecycleCoroutineScope;", "coroutineScope", "lifecycle-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class LifecycleKt {
    @NotNull
    public static final LifecycleCoroutineScope getCoroutineScope(@NotNull Lifecycle coroutineScope) {
        LifecycleCoroutineScopeImpl lifecycleCoroutineScopeImpl;
        Intrinsics.checkParameterIsNotNull(coroutineScope, "$this$coroutineScope");
        do {
            LifecycleCoroutineScopeImpl lifecycleCoroutineScopeImpl2 = (LifecycleCoroutineScopeImpl) coroutineScope.mInternalScopeRef.get();
            if (lifecycleCoroutineScopeImpl2 != null) {
                return lifecycleCoroutineScopeImpl2;
            }
            C3101t1 c3101t1 = new C3101t1(null);
            AbstractC3036c0 abstractC3036c0 = C3079m0.f8430a;
            lifecycleCoroutineScopeImpl = new LifecycleCoroutineScopeImpl(coroutineScope, CoroutineContext.Element.DefaultImpls.plus(c3101t1, C2964m.f8127b.mo3620U()));
        } while (!coroutineScope.mInternalScopeRef.compareAndSet(null, lifecycleCoroutineScopeImpl));
        lifecycleCoroutineScopeImpl.register();
        return lifecycleCoroutineScopeImpl;
    }
}
