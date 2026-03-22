package androidx.lifecycle;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\b&\u0018\u00002\u00020\u0001B\t\b\u0000¢\u0006\u0004\b\u0011\u0010\u0012J9\u0010\t\u001a\u00020\b2'\u0010\u0007\u001a#\b\u0001\u0012\u0004\u0012\u00020\u0001\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00040\u0003\u0012\u0006\u0012\u0004\u0018\u00010\u00050\u0002¢\u0006\u0002\b\u0006ø\u0001\u0000¢\u0006\u0004\b\t\u0010\nJ9\u0010\u000b\u001a\u00020\b2'\u0010\u0007\u001a#\b\u0001\u0012\u0004\u0012\u00020\u0001\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00040\u0003\u0012\u0006\u0012\u0004\u0018\u00010\u00050\u0002¢\u0006\u0002\b\u0006ø\u0001\u0000¢\u0006\u0004\b\u000b\u0010\nJ9\u0010\f\u001a\u00020\b2'\u0010\u0007\u001a#\b\u0001\u0012\u0004\u0012\u00020\u0001\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00040\u0003\u0012\u0006\u0012\u0004\u0018\u00010\u00050\u0002¢\u0006\u0002\b\u0006ø\u0001\u0000¢\u0006\u0004\b\f\u0010\nR\u0016\u0010\u0010\u001a\u00020\r8 @ X \u0004¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u000f\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0013"}, m5311d2 = {"Landroidx/lifecycle/LifecycleCoroutineScope;", "Lc/a/e0;", "Lkotlin/Function2;", "Lkotlin/coroutines/Continuation;", "", "", "Lkotlin/ExtensionFunctionType;", "block", "Lc/a/d1;", "launchWhenCreated", "(Lkotlin/jvm/functions/Function2;)Lc/a/d1;", "launchWhenStarted", "launchWhenResumed", "Landroidx/lifecycle/Lifecycle;", "getLifecycle$lifecycle_runtime_ktx_release", "()Landroidx/lifecycle/Lifecycle;", "lifecycle", "<init>", "()V", "lifecycle-runtime-ktx_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public abstract class LifecycleCoroutineScope implements InterfaceC3055e0 {
    @Override // p379c.p380a.InterfaceC3055e0
    @NotNull
    public abstract /* synthetic */ CoroutineContext getCoroutineContext();

    @NotNull
    public abstract Lifecycle getLifecycle$lifecycle_runtime_ktx_release();

    @NotNull
    public final InterfaceC3053d1 launchWhenCreated(@NotNull Function2<? super InterfaceC3055e0, ? super Continuation<? super Unit>, ? extends Object> block) {
        Intrinsics.checkParameterIsNotNull(block, "block");
        return C2354n.m2435U0(this, null, 0, new LifecycleCoroutineScope$launchWhenCreated$1(this, block, null), 3, null);
    }

    @NotNull
    public final InterfaceC3053d1 launchWhenResumed(@NotNull Function2<? super InterfaceC3055e0, ? super Continuation<? super Unit>, ? extends Object> block) {
        Intrinsics.checkParameterIsNotNull(block, "block");
        return C2354n.m2435U0(this, null, 0, new LifecycleCoroutineScope$launchWhenResumed$1(this, block, null), 3, null);
    }

    @NotNull
    public final InterfaceC3053d1 launchWhenStarted(@NotNull Function2<? super InterfaceC3055e0, ? super Continuation<? super Unit>, ? extends Object> block) {
        Intrinsics.checkParameterIsNotNull(block, "block");
        return C2354n.m2435U0(this, null, 0, new LifecycleCoroutineScope$launchWhenStarted$1(this, block, null), 3, null);
    }
}
