package p379c.p380a.p383b2;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.b2.l */
/* loaded from: classes2.dex */
public final class C3016l<T> extends AbstractC3005a<T> {

    /* renamed from: a */
    public final Function2<InterfaceC3007c<? super T>, Continuation<? super Unit>, Object> f8264a;

    /* JADX WARN: Multi-variable type inference failed */
    public C3016l(@NotNull Function2<? super InterfaceC3007c<? super T>, ? super Continuation<? super Unit>, ? extends Object> function2) {
        this.f8264a = function2;
    }

    @Override // p379c.p380a.p383b2.AbstractC3005a
    @Nullable
    /* renamed from: c */
    public Object mo3515c(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull Continuation<? super Unit> continuation) {
        Object invoke = this.f8264a.invoke(interfaceC3007c, continuation);
        return invoke == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? invoke : Unit.INSTANCE;
    }
}
