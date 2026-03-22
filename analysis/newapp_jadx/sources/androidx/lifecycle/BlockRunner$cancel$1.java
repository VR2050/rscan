package androidx.lifecycle;

import androidx.exifinterface.media.ExifInterface;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\u0010\u0005\u001a\u00020\u0002\"\u0004\b\u0000\u0010\u0000*\u00020\u0001H\u008a@¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "Lc/a/e0;", "", "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
@DebugMetadata(m5319c = "androidx.lifecycle.BlockRunner$cancel$1", m5320f = "CoroutineLiveData.kt", m5321i = {0}, m5322l = {Opcodes.NEW}, m5323m = "invokeSuspend", m5324n = {"$this$launch"}, m5325s = {"L$0"})
/* loaded from: classes.dex */
public final class BlockRunner$cancel$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public Object L$0;
    public int label;

    /* renamed from: p$ */
    private InterfaceC3055e0 f173p$;
    public final /* synthetic */ BlockRunner this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BlockRunner$cancel$1(BlockRunner blockRunner, Continuation continuation) {
        super(2, continuation);
        this.this$0 = blockRunner;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> completion) {
        Intrinsics.checkParameterIsNotNull(completion, "completion");
        BlockRunner$cancel$1 blockRunner$cancel$1 = new BlockRunner$cancel$1(this.this$0, completion);
        blockRunner$cancel$1.f173p$ = (InterfaceC3055e0) obj;
        return blockRunner$cancel$1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return ((BlockRunner$cancel$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        long j2;
        CoroutineLiveData coroutineLiveData;
        InterfaceC3053d1 interfaceC3053d1;
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            InterfaceC3055e0 interfaceC3055e0 = this.f173p$;
            j2 = this.this$0.timeoutInMs;
            this.L$0 = interfaceC3055e0;
            this.label = 1;
            if (C2354n.m2422Q(j2, this) == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
        }
        coroutineLiveData = this.this$0.liveData;
        if (!coroutineLiveData.hasActiveObservers()) {
            interfaceC3053d1 = this.this$0.runningJob;
            if (interfaceC3053d1 != null) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
            this.this$0.runningJob = null;
        }
        return Unit.INSTANCE;
    }
}
