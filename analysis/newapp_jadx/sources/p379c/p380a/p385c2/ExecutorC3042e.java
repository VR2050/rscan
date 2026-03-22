package p379c.p380a.p385c2;

import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.coroutines.CoroutineContext;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.AbstractC3106v0;
import p379c.p380a.RunnableC3061g0;

/* renamed from: c.a.c2.e */
/* loaded from: classes2.dex */
public final class ExecutorC3042e extends AbstractC3106v0 implements InterfaceC3046i, Executor {

    /* renamed from: c */
    public static final AtomicIntegerFieldUpdater f8371c = AtomicIntegerFieldUpdater.newUpdater(ExecutorC3042e.class, "inFlightTasks");

    /* renamed from: f */
    public final C3040c f8373f;

    /* renamed from: g */
    public final int f8374g;

    /* renamed from: h */
    public final String f8375h;

    /* renamed from: i */
    public final int f8376i;

    /* renamed from: e */
    public final ConcurrentLinkedQueue<Runnable> f8372e = new ConcurrentLinkedQueue<>();
    public volatile int inFlightTasks = 0;

    public ExecutorC3042e(@NotNull C3040c c3040c, int i2, @Nullable String str, int i3) {
        this.f8373f = c3040c;
        this.f8374g = i2;
        this.f8375h = str;
        this.f8376i = i3;
    }

    /* renamed from: U */
    public final void m3538U(Runnable runnable, boolean z) {
        do {
            AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = f8371c;
            if (atomicIntegerFieldUpdater.incrementAndGet(this) <= this.f8374g) {
                C3040c c3040c = this.f8373f;
                Objects.requireNonNull(c3040c);
                try {
                    c3040c.f8366c.m3527k(runnable, this, z);
                    return;
                } catch (RejectedExecutionException unused) {
                    RunnableC3061g0.f8400k.m3633c0(c3040c.f8366c.m3525d(runnable, this));
                    return;
                }
            }
            this.f8372e.add(runnable);
            if (atomicIntegerFieldUpdater.decrementAndGet(this) >= this.f8374g) {
                return;
            } else {
                runnable = this.f8372e.poll();
            }
        } while (runnable != null);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        throw new IllegalStateException("Close cannot be invoked on LimitingBlockingDispatcher".toString());
    }

    @Override // p379c.p380a.AbstractC3036c0
    public void dispatch(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        m3538U(runnable, false);
    }

    @Override // p379c.p380a.AbstractC3036c0
    public void dispatchYield(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        m3538U(runnable, true);
    }

    @Override // java.util.concurrent.Executor
    public void execute(@NotNull Runnable runnable) {
        m3538U(runnable, false);
    }

    @Override // p379c.p380a.p385c2.InterfaceC3046i
    /* renamed from: k */
    public void mo3539k() {
        Runnable poll = this.f8372e.poll();
        if (poll != null) {
            C3040c c3040c = this.f8373f;
            Objects.requireNonNull(c3040c);
            try {
                c3040c.f8366c.m3527k(poll, this, true);
                return;
            } catch (RejectedExecutionException unused) {
                RunnableC3061g0.f8400k.m3633c0(c3040c.f8366c.m3525d(poll, this));
                return;
            }
        }
        f8371c.decrementAndGet(this);
        Runnable poll2 = this.f8372e.poll();
        if (poll2 != null) {
            m3538U(poll2, true);
        }
    }

    @Override // p379c.p380a.AbstractC3036c0
    @NotNull
    public String toString() {
        String str = this.f8375h;
        if (str != null) {
            return str;
        }
        return super.toString() + "[dispatcher = " + this.f8373f + ']';
    }

    @Override // p379c.p380a.p385c2.InterfaceC3046i
    /* renamed from: v */
    public int mo3540v() {
        return this.f8376i;
    }
}
