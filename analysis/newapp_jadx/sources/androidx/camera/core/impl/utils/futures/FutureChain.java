package androidx.camera.core.impl.utils.futures;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.arch.core.util.Function;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.core.util.Preconditions;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public class FutureChain<V> implements InterfaceFutureC2413a<V> {

    @Nullable
    public CallbackToFutureAdapter.Completer<V> mCompleter;

    @NonNull
    private final InterfaceFutureC2413a<V> mDelegate;

    public FutureChain(@NonNull InterfaceFutureC2413a<V> interfaceFutureC2413a) {
        this.mDelegate = (InterfaceFutureC2413a) Preconditions.checkNotNull(interfaceFutureC2413a);
    }

    @NonNull
    public static <V> FutureChain<V> from(@NonNull InterfaceFutureC2413a<V> interfaceFutureC2413a) {
        return interfaceFutureC2413a instanceof FutureChain ? (FutureChain) interfaceFutureC2413a : new FutureChain<>(interfaceFutureC2413a);
    }

    public final void addCallback(@NonNull FutureCallback<? super V> futureCallback, @NonNull Executor executor) {
        Futures.addCallback(this, futureCallback, executor);
    }

    @Override // p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a
    public void addListener(@NonNull Runnable runnable, @NonNull Executor executor) {
        this.mDelegate.addListener(runnable, executor);
    }

    @Override // java.util.concurrent.Future
    public boolean cancel(boolean z) {
        return this.mDelegate.cancel(z);
    }

    @Override // java.util.concurrent.Future
    @Nullable
    public V get() {
        return this.mDelegate.get();
    }

    @Override // java.util.concurrent.Future
    public boolean isCancelled() {
        return this.mDelegate.isCancelled();
    }

    @Override // java.util.concurrent.Future
    public boolean isDone() {
        return this.mDelegate.isDone();
    }

    public boolean set(@Nullable V v) {
        CallbackToFutureAdapter.Completer<V> completer = this.mCompleter;
        if (completer != null) {
            return completer.set(v);
        }
        return false;
    }

    public boolean setException(@NonNull Throwable th) {
        CallbackToFutureAdapter.Completer<V> completer = this.mCompleter;
        if (completer != null) {
            return completer.setException(th);
        }
        return false;
    }

    @NonNull
    public final <T> FutureChain<T> transform(@NonNull Function<? super V, T> function, @NonNull Executor executor) {
        return (FutureChain) Futures.transform(this, function, executor);
    }

    @NonNull
    public final <T> FutureChain<T> transformAsync(@NonNull AsyncFunction<? super V, T> asyncFunction, @NonNull Executor executor) {
        return (FutureChain) Futures.transformAsync(this, asyncFunction, executor);
    }

    @Override // java.util.concurrent.Future
    @Nullable
    public V get(long j2, @NonNull TimeUnit timeUnit) {
        return this.mDelegate.get(j2, timeUnit);
    }

    public FutureChain() {
        this.mDelegate = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver<V>() { // from class: androidx.camera.core.impl.utils.futures.FutureChain.1
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public Object attachCompleter(@NonNull CallbackToFutureAdapter.Completer<V> completer) {
                Preconditions.checkState(FutureChain.this.mCompleter == null, "The result can only set once!");
                FutureChain.this.mCompleter = completer;
                StringBuilder m586H = C1499a.m586H("FutureChain[");
                m586H.append(FutureChain.this);
                m586H.append("]");
                return m586H.toString();
            }
        });
    }
}
