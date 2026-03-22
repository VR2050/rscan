package p379c.p380a;

import java.lang.Thread;
import java.util.Iterator;
import java.util.List;
import kotlin.ExceptionsKt__ExceptionsKt;
import kotlin.coroutines.CoroutineContext;
import kotlin.sequences.SequencesKt__SequencesKt;
import kotlin.sequences.SequencesKt___SequencesKt;
import kotlinx.coroutines.CoroutineExceptionHandler;
import org.jetbrains.annotations.NotNull;
import p000.C0000a;

/* renamed from: c.a.d0 */
/* loaded from: classes2.dex */
public final class C3052d0 {

    /* renamed from: a */
    public static final List<CoroutineExceptionHandler> f8392a = SequencesKt___SequencesKt.toList(SequencesKt__SequencesKt.asSequence(C0000a.m1b()));

    /* renamed from: a */
    public static final void m3549a(@NotNull CoroutineContext coroutineContext, @NotNull Throwable th) {
        Throwable runtimeException;
        Iterator<CoroutineExceptionHandler> it = f8392a.iterator();
        while (it.hasNext()) {
            try {
                it.next().handleException(coroutineContext, th);
            } catch (Throwable th2) {
                Thread currentThread = Thread.currentThread();
                Thread.UncaughtExceptionHandler uncaughtExceptionHandler = currentThread.getUncaughtExceptionHandler();
                if (th == th2) {
                    runtimeException = th;
                } else {
                    runtimeException = new RuntimeException("Exception while trying to handle coroutine exception", th2);
                    ExceptionsKt__ExceptionsKt.addSuppressed(runtimeException, th);
                }
                uncaughtExceptionHandler.uncaughtException(currentThread, runtimeException);
            }
        }
        Thread currentThread2 = Thread.currentThread();
        currentThread2.getUncaughtExceptionHandler().uncaughtException(currentThread2, th);
    }
}
