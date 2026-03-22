package androidx.work;

import androidx.annotation.RestrictTo;
import java.util.concurrent.ExecutionException;
import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.internal.InlineMarker;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;
import p379c.p380a.C3069j;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\n\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a#\u0010\u0002\u001a\u00028\u0000\"\u0004\b\u0000\u0010\u0000*\b\u0012\u0004\u0012\u00028\u00000\u0001H\u0087Hø\u0001\u0000¢\u0006\u0004\b\u0002\u0010\u0003\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0004"}, m5311d2 = {"R", "Lb/l/b/a/a/a;", "await", "(Lb/l/b/a/a/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "work-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class ListenableFutureKt {
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    @Nullable
    public static final <R> Object await(@NotNull InterfaceFutureC2413a<R> interfaceFutureC2413a, @NotNull Continuation<? super R> continuation) {
        if (interfaceFutureC2413a.isDone()) {
            try {
                return interfaceFutureC2413a.get();
            } catch (ExecutionException e2) {
                Throwable cause = e2.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw e2;
            }
        }
        C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
        interfaceFutureC2413a.addListener(new RunnableC0759x6ec15468(c3069j, interfaceFutureC2413a), DirectExecutor.INSTANCE);
        Object m3612u = c3069j.m3612u();
        if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return m3612u;
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    @Nullable
    private static final Object await$$forInline(@NotNull InterfaceFutureC2413a interfaceFutureC2413a, @NotNull Continuation continuation) {
        if (interfaceFutureC2413a.isDone()) {
            try {
                return interfaceFutureC2413a.get();
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
        interfaceFutureC2413a.addListener(new RunnableC0759x6ec15468(c3069j, interfaceFutureC2413a), DirectExecutor.INSTANCE);
        Object m3612u = c3069j.m3612u();
        if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        InlineMarker.mark(1);
        return m3612u;
    }
}
