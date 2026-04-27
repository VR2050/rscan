package io.reactivex.internal.schedulers;

import io.reactivex.disposables.Disposable;
import io.reactivex.internal.functions.Functions;
import io.reactivex.plugins.RxJavaPlugins;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicReference;

/* JADX INFO: loaded from: classes3.dex */
final class InstantPeriodicTask implements Callable<Void>, Disposable {
    static final FutureTask<Void> CANCELLED = new FutureTask<>(Functions.EMPTY_RUNNABLE, null);
    final ExecutorService executor;
    final AtomicReference<Future<?>> first = new AtomicReference<>();
    final AtomicReference<Future<?>> rest = new AtomicReference<>();
    Thread runner;
    final Runnable task;

    InstantPeriodicTask(Runnable task, ExecutorService executor) {
        this.task = task;
        this.executor = executor;
    }

    @Override // java.util.concurrent.Callable
    public Void call() throws Exception {
        try {
            this.runner = Thread.currentThread();
            try {
                this.task.run();
                setRest(this.executor.submit(this));
            } catch (Throwable ex) {
                RxJavaPlugins.onError(ex);
            }
            return null;
        } finally {
            this.runner = null;
        }
    }

    @Override // io.reactivex.disposables.Disposable
    public void dispose() {
        Future<?> current = this.first.getAndSet(CANCELLED);
        if (current != null && current != CANCELLED) {
            current.cancel(this.runner != Thread.currentThread());
        }
        Future<?> current2 = this.rest.getAndSet(CANCELLED);
        if (current2 != null && current2 != CANCELLED) {
            current2.cancel(this.runner != Thread.currentThread());
        }
    }

    @Override // io.reactivex.disposables.Disposable
    public boolean isDisposed() {
        return this.first.get() == CANCELLED;
    }

    void setFirst(Future<?> f) {
        Future<?> current;
        do {
            current = this.first.get();
            if (current == CANCELLED) {
                f.cancel(this.runner != Thread.currentThread());
            }
        } while (!this.first.compareAndSet(current, f));
    }

    void setRest(Future<?> f) {
        Future<?> current;
        do {
            current = this.rest.get();
            if (current == CANCELLED) {
                f.cancel(this.runner != Thread.currentThread());
            }
        } while (!this.rest.compareAndSet(current, f));
    }
}
