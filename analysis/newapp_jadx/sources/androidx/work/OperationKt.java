package androidx.work;

import androidx.work.Operation;
import java.util.concurrent.ExecutionException;
import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;
import p379c.p380a.C3069j;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a\u001f\u0010\u0003\u001a\n \u0002*\u0004\u0018\u00010\u00010\u0001*\u00020\u0000H\u0086Hø\u0001\u0000¢\u0006\u0004\b\u0003\u0010\u0004\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0005"}, m5311d2 = {"Landroidx/work/Operation;", "Landroidx/work/Operation$State$SUCCESS;", "kotlin.jvm.PlatformType", "await", "(Landroidx/work/Operation;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "work-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class OperationKt {
    @Nullable
    public static final Object await(@NotNull Operation operation, @NotNull Continuation<? super Operation.State.SUCCESS> continuation) {
        InterfaceFutureC2413a<Operation.State.SUCCESS> result = operation.getResult();
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        if (result.isDone()) {
            try {
                return result.get();
            } catch (ExecutionException e2) {
                Throwable cause = e2.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw e2;
            }
        }
        C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
        result.addListener(new OperationKt$await$$inlined$suspendCancellableCoroutine$lambda$1(c3069j, result), DirectExecutor.INSTANCE);
        Object m3612u = c3069j.m3612u();
        if (m3612u != IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            return m3612u;
        }
        DebugProbesKt.probeCoroutineSuspended(continuation);
        return m3612u;
    }

    @Nullable
    private static final Object await$$forInline(@NotNull Operation operation, @NotNull Continuation continuation) {
        InterfaceFutureC2413a<Operation.State.SUCCESS> result = operation.getResult();
        Intrinsics.checkExpressionValueIsNotNull(result, "result");
        if (result.isDone()) {
            try {
                return result.get();
            } catch (ExecutionException e2) {
                Throwable cause = e2.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw e2;
            }
        }
        InlineMarker.mark(0);
        C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
        result.addListener(new OperationKt$await$$inlined$suspendCancellableCoroutine$lambda$1(c3069j, result), DirectExecutor.INSTANCE);
        Object m3612u = c3069j.m3612u();
        if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        InlineMarker.mark(1);
        return m3612u;
    }
}
