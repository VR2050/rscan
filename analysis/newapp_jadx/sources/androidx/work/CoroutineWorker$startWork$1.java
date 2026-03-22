package androidx.work;

import androidx.work.ListenableWorker;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3055e0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\u0010\u0004\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
@DebugMetadata(m5319c = "androidx.work.CoroutineWorker$startWork$1", m5320f = "CoroutineWorker.kt", m5321i = {0}, m5322l = {68}, m5323m = "invokeSuspend", m5324n = {"$this$launch"}, m5325s = {"L$0"})
/* loaded from: classes.dex */
public final class CoroutineWorker$startWork$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public Object L$0;
    public int label;

    /* renamed from: p$ */
    private InterfaceC3055e0 f209p$;
    public final /* synthetic */ CoroutineWorker this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CoroutineWorker$startWork$1(CoroutineWorker coroutineWorker, Continuation continuation) {
        super(2, continuation);
        this.this$0 = coroutineWorker;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
        Intrinsics.checkParameterIsNotNull(completion, "completion");
        CoroutineWorker$startWork$1 coroutineWorker$startWork$1 = new CoroutineWorker$startWork$1(this.this$0, completion);
        coroutineWorker$startWork$1.f209p$ = (InterfaceC3055e0) obj;
        return coroutineWorker$startWork$1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return ((CoroutineWorker$startWork$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        try {
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                InterfaceC3055e0 interfaceC3055e0 = this.f209p$;
                CoroutineWorker coroutineWorker = this.this$0;
                this.L$0 = interfaceC3055e0;
                this.label = 1;
                obj = coroutineWorker.doWork(this);
                if (obj == coroutine_suspended) {
                    return coroutine_suspended;
                }
            } else {
                if (i2 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                ResultKt.throwOnFailure(obj);
            }
            this.this$0.getFuture$work_runtime_ktx_release().set((ListenableWorker.Result) obj);
        } catch (Throwable th) {
            this.this$0.getFuture$work_runtime_ktx_release().setException(th);
        }
        return Unit.INSTANCE;
    }
}
