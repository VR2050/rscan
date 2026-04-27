package io.reactivex.internal.schedulers;

import io.reactivex.disposables.Disposable;
import io.reactivex.internal.disposables.DisposableContainer;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReferenceArray;

/* JADX INFO: loaded from: classes3.dex */
public final class ScheduledRunnable extends AtomicReferenceArray<Object> implements Runnable, Callable<Object>, Disposable {
    static final Object DISPOSED = new Object();
    static final Object DONE = new Object();
    static final int FUTURE_INDEX = 1;
    static final int PARENT_INDEX = 0;
    static final int THREAD_INDEX = 2;
    private static final long serialVersionUID = -6120223772001106981L;
    final Runnable actual;

    public ScheduledRunnable(Runnable actual, DisposableContainer parent) {
        super(3);
        this.actual = actual;
        lazySet(0, parent);
    }

    @Override // java.util.concurrent.Callable
    public Object call() {
        run();
        return null;
    }

    @Override // java.lang.Runnable
    public void run() {
        Object o;
        Object obj;
        boolean zCompareAndSet;
        Object o2;
        lazySet(2, Thread.currentThread());
        try {
            this.actual.run();
        } finally {
            try {
            } catch (Throwable th) {
                do {
                    if (o == obj) {
                        break;
                    }
                } while (!zCompareAndSet);
            }
        }
        lazySet(2, null);
        Object o3 = get(0);
        if (o3 != DISPOSED && o3 != null && compareAndSet(0, o3, DONE)) {
            ((DisposableContainer) o3).delete(this);
        }
        do {
            o2 = get(1);
            if (o2 == DISPOSED) {
                return;
            }
        } while (!compareAndSet(1, o2, DONE));
    }

    public void setFuture(Future<?> f) {
        Object o;
        do {
            o = get(1);
            if (o == DONE) {
                return;
            }
            if (o == DISPOSED) {
                f.cancel(get(2) != Thread.currentThread());
                return;
            }
        } while (!compareAndSet(1, o, f));
    }

    @Override // io.reactivex.disposables.Disposable
    public void dispose() {
        Object o;
        Object obj;
        Object obj2;
        while (true) {
            Object o2 = get(1);
            if (o2 == DONE || o2 == (obj2 = DISPOSED)) {
                break;
            } else if (compareAndSet(1, o2, obj2)) {
                if (o2 != null) {
                    ((Future) o2).cancel(get(2) != Thread.currentThread());
                }
            }
        }
        do {
            o = get(0);
            if (o == DONE || o == (obj = DISPOSED) || o == null) {
                return;
            }
        } while (!compareAndSet(0, o, obj));
        ((DisposableContainer) o).delete(this);
    }

    @Override // io.reactivex.disposables.Disposable
    public boolean isDisposed() {
        Object o = get(1);
        return o == DISPOSED || o == DONE;
    }
}
