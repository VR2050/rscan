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
import p379c.p380a.p382a2.InterfaceC2992o;

/* JADX INFO: Add missing generic type declarations: [T] */
@DebugMetadata(m5319c = "kotlinx.coroutines.flow.internal.ChannelFlow$collectToFun$1", m5320f = "ChannelFlow.kt", m5321i = {0}, m5322l = {60}, m5323m = "invokeSuspend", m5324n = {"it"}, m5325s = {"L$0"})
/* renamed from: c.a.b2.n.c */
/* loaded from: classes2.dex */
public final class C3020c<T> extends SuspendLambda implements Function2<InterfaceC2992o<? super T>, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public InterfaceC2992o f8275c;

    /* renamed from: e */
    public Object f8276e;

    /* renamed from: f */
    public int f8277f;

    /* renamed from: g */
    public final /* synthetic */ AbstractC3019b f8278g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3020c(AbstractC3019b abstractC3019b, Continuation continuation) {
        super(2, continuation);
        this.f8278g = abstractC3019b;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        C3020c c3020c = new C3020c(this.f8278g, continuation);
        c3020c.f8275c = (InterfaceC2992o) obj;
        return c3020c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Continuation<? super Unit> continuation) {
        C3020c c3020c = new C3020c(this.f8278g, continuation);
        c3020c.f8275c = (InterfaceC2992o) obj;
        return c3020c.invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f8277f;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC2992o<? super T> interfaceC2992o = this.f8275c;
            AbstractC3019b abstractC3019b = this.f8278g;
            this.f8276e = interfaceC2992o;
            this.f8277f = 1;
            if (abstractC3019b.mo3517c(interfaceC2992o, this) == coroutine_suspended) {
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
