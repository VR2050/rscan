package p379c.p380a.p383b2.p384n;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p382a2.EnumC2982e;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.f */
/* loaded from: classes2.dex */
public final class C3023f<T> extends AbstractC3022e<T, T> {
    public C3023f(InterfaceC3006b interfaceC3006b, CoroutineContext coroutineContext, int i2, EnumC2982e enumC2982e, int i3) {
        super(interfaceC3006b, (i3 & 2) != 0 ? EmptyCoroutineContext.INSTANCE : coroutineContext, (i3 & 4) != 0 ? -3 : i2, (i3 & 8) != 0 ? EnumC2982e.SUSPEND : null);
    }

    @Override // p379c.p380a.p383b2.p384n.AbstractC3019b
    @NotNull
    /* renamed from: d */
    public AbstractC3019b<T> mo3518d(@NotNull CoroutineContext coroutineContext, int i2, @NotNull EnumC2982e enumC2982e) {
        return new C3023f(this.f8283d, coroutineContext, i2, enumC2982e);
    }

    @Override // p379c.p380a.p383b2.p384n.AbstractC3022e
    @Nullable
    /* renamed from: e */
    public Object mo3519e(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull Continuation<? super Unit> continuation) {
        Object mo289a = this.f8283d.mo289a(interfaceC3007c, continuation);
        return mo289a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo289a : Unit.INSTANCE;
    }

    public C3023f(@NotNull InterfaceC3006b<? extends T> interfaceC3006b, @NotNull CoroutineContext coroutineContext, int i2, @NotNull EnumC2982e enumC2982e) {
        super(interfaceC3006b, coroutineContext, i2, enumC2982e);
    }
}
