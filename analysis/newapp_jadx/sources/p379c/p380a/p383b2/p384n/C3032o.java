package p379c.p380a.p383b2.p384n;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p382a2.InterfaceC2998u;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.o */
/* loaded from: classes2.dex */
public final class C3032o<T> implements InterfaceC3007c<T> {

    /* renamed from: c */
    public final InterfaceC2998u<T> f8333c;

    /* JADX WARN: Multi-variable type inference failed */
    public C3032o(@NotNull InterfaceC2998u<? super T> interfaceC2998u) {
        this.f8333c = interfaceC2998u;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3007c
    @Nullable
    public Object emit(T t, @NotNull Continuation<? super Unit> continuation) {
        Object mo3484p = this.f8333c.mo3484p(t, continuation);
        return mo3484p == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo3484p : Unit.INSTANCE;
    }
}
