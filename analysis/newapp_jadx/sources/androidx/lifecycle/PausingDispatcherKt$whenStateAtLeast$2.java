package androidx.lifecycle;

import androidx.exifinterface.media.ExifInterface;
import androidx.lifecycle.Lifecycle;
import com.alibaba.fastjson.asm.Opcodes;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;

/* JADX INFO: Add missing generic type declarations: [T] */
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\n\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u0010\u0004\u001a\u00028\u0000\"\u0004\b\u0000\u0010\u0000*\u00020\u0001H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "Lc/a/e0;", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
@DebugMetadata(m5319c = "androidx.lifecycle.PausingDispatcherKt$whenStateAtLeast$2", m5320f = "PausingDispatcher.kt", m5321i = {0, 0, 0, 0}, m5322l = {Opcodes.IF_ICMPGT}, m5323m = "invokeSuspend", m5324n = {"$this$withContext", "job", "dispatcher", "controller"}, m5325s = {"L$0", "L$1", "L$2", "L$3"})
/* loaded from: classes.dex */
public final class PausingDispatcherKt$whenStateAtLeast$2<T> extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super T>, Object> {
    public final /* synthetic */ Function2 $block;
    public final /* synthetic */ Lifecycle.State $minState;
    public final /* synthetic */ Lifecycle $this_whenStateAtLeast;
    public Object L$0;
    public Object L$1;
    public Object L$2;
    public Object L$3;
    public int label;

    /* renamed from: p$ */
    private InterfaceC3055e0 f188p$;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PausingDispatcherKt$whenStateAtLeast$2(Lifecycle lifecycle, Lifecycle.State state, Function2 function2, Continuation continuation) {
        super(2, continuation);
        this.$this_whenStateAtLeast = lifecycle;
        this.$minState = state;
        this.$block = function2;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
        Intrinsics.checkParameterIsNotNull(completion, "completion");
        PausingDispatcherKt$whenStateAtLeast$2 pausingDispatcherKt$whenStateAtLeast$2 = new PausingDispatcherKt$whenStateAtLeast$2(this.$this_whenStateAtLeast, this.$minState, this.$block, completion);
        pausingDispatcherKt$whenStateAtLeast$2.f188p$ = (InterfaceC3055e0) obj;
        return pausingDispatcherKt$whenStateAtLeast$2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Object obj) {
        return ((PausingDispatcherKt$whenStateAtLeast$2) create(interfaceC3055e0, (Continuation) obj)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        LifecycleController lifecycleController;
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3055e0 interfaceC3055e0 = this.f188p$;
            InterfaceC3053d1 interfaceC3053d1 = (InterfaceC3053d1) interfaceC3055e0.getCoroutineContext().get(InterfaceC3053d1.f8393b);
            if (interfaceC3053d1 == null) {
                throw new IllegalStateException("when[State] methods should have a parent job".toString());
            }
            PausingDispatcher pausingDispatcher = new PausingDispatcher();
            LifecycleController lifecycleController2 = new LifecycleController(this.$this_whenStateAtLeast, this.$minState, pausingDispatcher.dispatchQueue, interfaceC3053d1);
            try {
                Function2 function2 = this.$block;
                this.L$0 = interfaceC3055e0;
                this.L$1 = interfaceC3053d1;
                this.L$2 = pausingDispatcher;
                this.L$3 = lifecycleController2;
                this.label = 1;
                obj = C2354n.m2471e2(pausingDispatcher, function2, this);
                if (obj == coroutine_suspended) {
                    return coroutine_suspended;
                }
                lifecycleController = lifecycleController2;
            } catch (Throwable th) {
                th = th;
                lifecycleController = lifecycleController2;
                lifecycleController.finish();
                throw th;
            }
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            lifecycleController = (LifecycleController) this.L$3;
            try {
                ResultKt.throwOnFailure(obj);
            } catch (Throwable th2) {
                th = th2;
                lifecycleController.finish();
                throw th;
            }
        }
        lifecycleController.finish();
        return obj;
    }
}
