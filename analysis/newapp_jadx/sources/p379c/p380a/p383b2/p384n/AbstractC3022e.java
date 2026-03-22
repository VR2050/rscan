package p379c.p380a.p383b2.p384n;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.ContinuationInterceptor;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2952a;
import p379c.p380a.p382a2.EnumC2982e;
import p379c.p380a.p382a2.InterfaceC2992o;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.e */
/* loaded from: classes2.dex */
public abstract class AbstractC3022e<S, T> extends AbstractC3019b<T> {

    /* renamed from: d */
    @JvmField
    @NotNull
    public final InterfaceC3006b<S> f8283d;

    /* JADX WARN: Multi-variable type inference failed */
    public AbstractC3022e(@NotNull InterfaceC3006b<? extends S> interfaceC3006b, @NotNull CoroutineContext coroutineContext, int i2, @NotNull EnumC2982e enumC2982e) {
        super(coroutineContext, i2, enumC2982e);
        this.f8283d = interfaceC3006b;
    }

    @Override // p379c.p380a.p383b2.p384n.AbstractC3019b, p379c.p380a.p383b2.InterfaceC3006b
    @Nullable
    /* renamed from: a */
    public Object mo289a(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull Continuation<? super Unit> continuation) {
        if (this.f8268b == -3) {
            CoroutineContext coroutineContext = continuation.get$context();
            CoroutineContext plus = coroutineContext.plus(this.f8267a);
            if (Intrinsics.areEqual(plus, coroutineContext)) {
                Object mo3519e = mo3519e(interfaceC3007c, continuation);
                return mo3519e == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo3519e : Unit.INSTANCE;
            }
            ContinuationInterceptor.Companion companion = ContinuationInterceptor.INSTANCE;
            if (Intrinsics.areEqual((ContinuationInterceptor) plus.get(companion), (ContinuationInterceptor) coroutineContext.get(companion))) {
                CoroutineContext coroutineContext2 = continuation.get$context();
                if (!(interfaceC3007c instanceof C3032o)) {
                    interfaceC3007c = new C3034q(interfaceC3007c, coroutineContext2);
                }
                Object m2475f2 = C2354n.m2475f2(plus, interfaceC3007c, C2952a.m3413b(plus), new C3021d(this, null), continuation);
                if (m2475f2 != IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                    m2475f2 = Unit.INSTANCE;
                }
                return m2475f2 == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m2475f2 : Unit.INSTANCE;
            }
        }
        Object mo289a = super.mo289a(interfaceC3007c, continuation);
        return mo289a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo289a : Unit.INSTANCE;
    }

    @Override // p379c.p380a.p383b2.p384n.AbstractC3019b
    @Nullable
    /* renamed from: c */
    public Object mo3517c(@NotNull InterfaceC2992o<? super T> interfaceC2992o, @NotNull Continuation<? super Unit> continuation) {
        Object mo3519e = mo3519e(new C3032o(interfaceC2992o), continuation);
        return mo3519e == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo3519e : Unit.INSTANCE;
    }

    @Nullable
    /* renamed from: e */
    public abstract Object mo3519e(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull Continuation<? super Unit> continuation);

    @Override // p379c.p380a.p383b2.p384n.AbstractC3019b
    @NotNull
    public String toString() {
        return this.f8283d + " -> " + super.toString();
    }
}
