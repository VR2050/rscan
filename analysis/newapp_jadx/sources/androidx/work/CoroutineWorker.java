package androidx.work;

import android.content.Context;
import androidx.work.ListenableWorker;
import androidx.work.impl.utils.futures.SettableFuture;
import androidx.work.impl.utils.taskexecutor.TaskExecutor;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;
import p379c.p380a.AbstractC3036c0;
import p379c.p380a.C3069j;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3066i;
import p379c.p380a.InterfaceC3102u;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000P\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\b&\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010$\u001a\u00020#\u0012\u0006\u0010&\u001a\u00020%¢\u0006\u0004\b'\u0010(J\u0013\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0013\u0010\u0006\u001a\u00020\u0003H¦@ø\u0001\u0000¢\u0006\u0004\b\u0006\u0010\u0007J\u001b\u0010\u000b\u001a\u00020\n2\u0006\u0010\t\u001a\u00020\bH\u0086@ø\u0001\u0000¢\u0006\u0004\b\u000b\u0010\fJ\u001b\u0010\u000f\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\rH\u0086@ø\u0001\u0000¢\u0006\u0004\b\u000f\u0010\u0010J\r\u0010\u0011\u001a\u00020\n¢\u0006\u0004\b\u0011\u0010\u0012R\"\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00030\u00138\u0000@\u0000X\u0080\u0004¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017R\u001c\u0010\u0019\u001a\u00020\u00188\u0000@\u0000X\u0080\u0004¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\"\u0010\u001e\u001a\u00020\u001d8\u0016@\u0017X\u0097\u0004¢\u0006\u0012\n\u0004\b\u001e\u0010\u001f\u0012\u0004\b\"\u0010\u0012\u001a\u0004\b \u0010!\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006)"}, m5311d2 = {"Landroidx/work/CoroutineWorker;", "Landroidx/work/ListenableWorker;", "Lb/l/b/a/a/a;", "Landroidx/work/ListenableWorker$Result;", "startWork", "()Lb/l/b/a/a/a;", "doWork", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "Landroidx/work/Data;", "data", "", "setProgress", "(Landroidx/work/Data;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "Landroidx/work/ForegroundInfo;", "foregroundInfo", "setForeground", "(Landroidx/work/ForegroundInfo;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "onStopped", "()V", "Landroidx/work/impl/utils/futures/SettableFuture;", "future", "Landroidx/work/impl/utils/futures/SettableFuture;", "getFuture$work_runtime_ktx_release", "()Landroidx/work/impl/utils/futures/SettableFuture;", "Lc/a/u;", "job", "Lc/a/u;", "getJob$work_runtime_ktx_release", "()Lc/a/u;", "Lc/a/c0;", "coroutineContext", "Lc/a/c0;", "getCoroutineContext", "()Lc/a/c0;", "coroutineContext$annotations", "Landroid/content/Context;", "appContext", "Landroidx/work/WorkerParameters;", VideoListActivity.KEY_PARAMS, "<init>", "(Landroid/content/Context;Landroidx/work/WorkerParameters;)V", "work-runtime-ktx_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public abstract class CoroutineWorker extends ListenableWorker {

    @NotNull
    private final AbstractC3036c0 coroutineContext;

    @NotNull
    private final SettableFuture<ListenableWorker.Result> future;

    @NotNull
    private final InterfaceC3102u job;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CoroutineWorker(@NotNull Context appContext, @NotNull WorkerParameters params) {
        super(appContext, params);
        Intrinsics.checkParameterIsNotNull(appContext, "appContext");
        Intrinsics.checkParameterIsNotNull(params, "params");
        this.job = C2354n.m2460c(null, 1, null);
        SettableFuture<ListenableWorker.Result> create = SettableFuture.create();
        Intrinsics.checkExpressionValueIsNotNull(create, "SettableFuture.create()");
        this.future = create;
        Runnable runnable = new Runnable() { // from class: androidx.work.CoroutineWorker.1
            @Override // java.lang.Runnable
            public final void run() {
                if (CoroutineWorker.this.getFuture$work_runtime_ktx_release().isCancelled()) {
                    C2354n.m2512s(CoroutineWorker.this.getJob(), null, 1, null);
                }
            }
        };
        TaskExecutor taskExecutor = getTaskExecutor();
        Intrinsics.checkExpressionValueIsNotNull(taskExecutor, "taskExecutor");
        create.addListener(runnable, taskExecutor.getBackgroundExecutor());
        this.coroutineContext = C3079m0.f8430a;
    }

    @Deprecated(message = "use withContext(...) inside doWork() instead.")
    public static /* synthetic */ void coroutineContext$annotations() {
    }

    @Nullable
    public abstract Object doWork(@NotNull Continuation<? super ListenableWorker.Result> continuation);

    @NotNull
    public AbstractC3036c0 getCoroutineContext() {
        return this.coroutineContext;
    }

    @NotNull
    public final SettableFuture<ListenableWorker.Result> getFuture$work_runtime_ktx_release() {
        return this.future;
    }

    @NotNull
    /* renamed from: getJob$work_runtime_ktx_release, reason: from getter */
    public final InterfaceC3102u getJob() {
        return this.job;
    }

    @Override // androidx.work.ListenableWorker
    public final void onStopped() {
        super.onStopped();
        this.future.cancel(false);
    }

    @Nullable
    public final Object setForeground(@NotNull ForegroundInfo foregroundInfo, @NotNull Continuation<? super Unit> continuation) {
        Object obj;
        final InterfaceFutureC2413a<Void> foregroundAsync = setForegroundAsync(foregroundInfo);
        Intrinsics.checkExpressionValueIsNotNull(foregroundAsync, "setForegroundAsync(foregroundInfo)");
        if (foregroundAsync.isDone()) {
            try {
                obj = foregroundAsync.get();
            } catch (ExecutionException e2) {
                Throwable cause = e2.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw e2;
            }
        } else {
            final C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
            foregroundAsync.addListener(new Runnable() { // from class: androidx.work.CoroutineWorker$await$$inlined$suspendCancellableCoroutine$lambda$2
                @Override // java.lang.Runnable
                public final void run() {
                    try {
                        InterfaceC3066i interfaceC3066i = InterfaceC3066i.this;
                        V v = foregroundAsync.get();
                        Result.Companion companion = Result.INSTANCE;
                        interfaceC3066i.resumeWith(Result.m6055constructorimpl(v));
                    } catch (Throwable th) {
                        Throwable cause2 = th.getCause();
                        if (cause2 == null) {
                            cause2 = th;
                        }
                        if (th instanceof CancellationException) {
                            InterfaceC3066i.this.mo3566l(cause2);
                            return;
                        }
                        InterfaceC3066i interfaceC3066i2 = InterfaceC3066i.this;
                        Result.Companion companion2 = Result.INSTANCE;
                        interfaceC3066i2.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(cause2)));
                    }
                }
            }, DirectExecutor.INSTANCE);
            obj = c3069j.m3612u();
            if (obj == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                DebugProbesKt.probeCoroutineSuspended(continuation);
            }
        }
        return obj == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? obj : Unit.INSTANCE;
    }

    @Nullable
    public final Object setProgress(@NotNull Data data, @NotNull Continuation<? super Unit> continuation) {
        Object obj;
        final InterfaceFutureC2413a<Void> progressAsync = setProgressAsync(data);
        Intrinsics.checkExpressionValueIsNotNull(progressAsync, "setProgressAsync(data)");
        if (progressAsync.isDone()) {
            try {
                obj = progressAsync.get();
            } catch (ExecutionException e2) {
                Throwable cause = e2.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw e2;
            }
        } else {
            final C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
            progressAsync.addListener(new Runnable() { // from class: androidx.work.CoroutineWorker$await$$inlined$suspendCancellableCoroutine$lambda$1
                @Override // java.lang.Runnable
                public final void run() {
                    try {
                        InterfaceC3066i interfaceC3066i = InterfaceC3066i.this;
                        V v = progressAsync.get();
                        Result.Companion companion = Result.INSTANCE;
                        interfaceC3066i.resumeWith(Result.m6055constructorimpl(v));
                    } catch (Throwable th) {
                        Throwable cause2 = th.getCause();
                        if (cause2 == null) {
                            cause2 = th;
                        }
                        if (th instanceof CancellationException) {
                            InterfaceC3066i.this.mo3566l(cause2);
                            return;
                        }
                        InterfaceC3066i interfaceC3066i2 = InterfaceC3066i.this;
                        Result.Companion companion2 = Result.INSTANCE;
                        interfaceC3066i2.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(cause2)));
                    }
                }
            }, DirectExecutor.INSTANCE);
            obj = c3069j.m3612u();
            if (obj == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                DebugProbesKt.probeCoroutineSuspended(continuation);
            }
        }
        return obj == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? obj : Unit.INSTANCE;
    }

    @Override // androidx.work.ListenableWorker
    @NotNull
    public final InterfaceFutureC2413a<ListenableWorker.Result> startWork() {
        C2354n.m2435U0(C2354n.m2456b(getCoroutineContext().plus(this.job)), null, 0, new CoroutineWorker$startWork$1(this, null), 3, null);
        return this.future;
    }
}
