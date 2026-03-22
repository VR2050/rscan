package p379c.p380a.p383b2.p384n;

import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p383b2.InterfaceC3007c;

/* JADX INFO: Add missing generic type declarations: [T] */
@DebugMetadata(m5319c = "kotlinx.coroutines.flow.internal.ChannelFlowOperator$collectWithContextUndispatched$2", m5320f = "ChannelFlow.kt", m5321i = {0}, m5322l = {164}, m5323m = "invokeSuspend", m5324n = {"it"}, m5325s = {"L$0"})
/* renamed from: c.a.b2.n.d */
/* loaded from: classes2.dex */
public final class C3021d<T> extends SuspendLambda implements Function2<InterfaceC3007c<? super T>, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public InterfaceC3007c f8279c;

    /* renamed from: e */
    public Object f8280e;

    /* renamed from: f */
    public int f8281f;

    /* renamed from: g */
    public final /* synthetic */ AbstractC3022e f8282g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3021d(AbstractC3022e abstractC3022e, Continuation continuation) {
        super(2, continuation);
        this.f8282g = abstractC3022e;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        C3021d c3021d = new C3021d(this.f8282g, continuation);
        c3021d.f8279c = (InterfaceC3007c) obj;
        return c3021d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Continuation<? super Unit> continuation) {
        C3021d c3021d = new C3021d(this.f8282g, continuation);
        c3021d.f8279c = (InterfaceC3007c) obj;
        return c3021d.invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f8281f;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3007c<? super T> interfaceC3007c = this.f8279c;
            AbstractC3022e abstractC3022e = this.f8282g;
            this.f8280e = interfaceC3007c;
            this.f8281f = 1;
            if (abstractC3022e.mo3519e(interfaceC3007c, this) == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
        }
        return Unit.INSTANCE;
    }
}
