package androidx.work;

import java.util.concurrent.CancellationException;
import kotlin.Metadata;
import kotlin.Result;
import kotlin.ResultKt;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;
import p379c.p380a.InterfaceC3066i;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\n\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\u0010\u0005\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0000H\n¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, m5311d2 = {"R", "", "run", "()V", "androidx/work/ListenableFutureKt$await$2$1", "<anonymous>"}, m5312k = 3, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class OperationKt$await$$inlined$suspendCancellableCoroutine$lambda$1 implements Runnable {
    public final /* synthetic */ InterfaceC3066i $cancellableContinuation;
    public final /* synthetic */ InterfaceFutureC2413a $this_await$inlined;

    public OperationKt$await$$inlined$suspendCancellableCoroutine$lambda$1(InterfaceC3066i interfaceC3066i, InterfaceFutureC2413a interfaceFutureC2413a) {
        this.$cancellableContinuation = interfaceC3066i;
        this.$this_await$inlined = interfaceFutureC2413a;
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            InterfaceC3066i interfaceC3066i = this.$cancellableContinuation;
            V v = this.$this_await$inlined.get();
            Result.Companion companion = Result.INSTANCE;
            interfaceC3066i.resumeWith(Result.m6055constructorimpl(v));
        } catch (Throwable th) {
            Throwable cause = th.getCause();
            if (cause == null) {
                cause = th;
            }
            if (th instanceof CancellationException) {
                this.$cancellableContinuation.mo3566l(cause);
                return;
            }
            InterfaceC3066i interfaceC3066i2 = this.$cancellableContinuation;
            Result.Companion companion2 = Result.INSTANCE;
            interfaceC3066i2.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(cause)));
        }
    }
}
