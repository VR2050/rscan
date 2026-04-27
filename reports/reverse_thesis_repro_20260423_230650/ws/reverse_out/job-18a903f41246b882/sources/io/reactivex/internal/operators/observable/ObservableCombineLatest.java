package io.reactivex.internal.operators.observable;

import io.reactivex.Observable;
import io.reactivex.ObservableSource;
import io.reactivex.Observer;
import io.reactivex.disposables.Disposable;
import io.reactivex.exceptions.Exceptions;
import io.reactivex.functions.Function;
import io.reactivex.internal.disposables.DisposableHelper;
import io.reactivex.internal.disposables.EmptyDisposable;
import io.reactivex.internal.functions.ObjectHelper;
import io.reactivex.internal.queue.SpscLinkedArrayQueue;
import io.reactivex.internal.util.AtomicThrowable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* JADX INFO: loaded from: classes3.dex */
public final class ObservableCombineLatest<T, R> extends Observable<R> {
    final int bufferSize;
    final Function<? super Object[], ? extends R> combiner;
    final boolean delayError;
    final ObservableSource<? extends T>[] sources;
    final Iterable<? extends ObservableSource<? extends T>> sourcesIterable;

    public ObservableCombineLatest(ObservableSource<? extends T>[] sources, Iterable<? extends ObservableSource<? extends T>> sourcesIterable, Function<? super Object[], ? extends R> combiner, int bufferSize, boolean delayError) {
        this.sources = sources;
        this.sourcesIterable = sourcesIterable;
        this.combiner = combiner;
        this.bufferSize = bufferSize;
        this.delayError = delayError;
    }

    @Override // io.reactivex.Observable
    public void subscribeActual(Observer<? super R> s) {
        int count;
        ObservableSource<? extends T>[] sources = this.sources;
        int count2 = 0;
        if (sources == null) {
            sources = new Observable[8];
            for (ObservableSource<? extends T> p : this.sourcesIterable) {
                if (count2 == sources.length) {
                    ObservableSource<? extends T>[] b = new ObservableSource[(count2 >> 2) + count2];
                    System.arraycopy(sources, 0, b, 0, count2);
                    sources = b;
                }
                sources[count2] = p;
                count2++;
            }
            count = count2;
        } else {
            int count3 = sources.length;
            count = count3;
        }
        if (count == 0) {
            EmptyDisposable.complete(s);
            return;
        }
        LatestCoordinator<T, R> lc = new LatestCoordinator<>(s, this.combiner, count, this.bufferSize, this.delayError);
        lc.subscribe(sources);
    }

    static final class LatestCoordinator<T, R> extends AtomicInteger implements Disposable {
        private static final long serialVersionUID = 8567835998786448817L;
        int active;
        final Observer<? super R> actual;
        volatile boolean cancelled;
        final Function<? super Object[], ? extends R> combiner;
        int complete;
        final boolean delayError;
        volatile boolean done;
        final AtomicThrowable errors = new AtomicThrowable();
        Object[] latest;
        final CombinerObserver<T, R>[] observers;
        final SpscLinkedArrayQueue<Object[]> queue;

        LatestCoordinator(Observer<? super R> actual, Function<? super Object[], ? extends R> combiner, int count, int bufferSize, boolean delayError) {
            this.actual = actual;
            this.combiner = combiner;
            this.delayError = delayError;
            this.latest = new Object[count];
            CombinerObserver<T, R>[] as = new CombinerObserver[count];
            for (int i = 0; i < count; i++) {
                as[i] = new CombinerObserver<>(this, i);
            }
            this.observers = as;
            this.queue = new SpscLinkedArrayQueue<>(bufferSize);
        }

        public void subscribe(ObservableSource<? extends T>[] sources) {
            CombinerObserver<T, R>[] combinerObserverArr = this.observers;
            int len = combinerObserverArr.length;
            this.actual.onSubscribe(this);
            for (int i = 0; i < len && !this.done && !this.cancelled; i++) {
                sources[i].subscribe(combinerObserverArr[i]);
            }
        }

        @Override // io.reactivex.disposables.Disposable
        public void dispose() {
            if (!this.cancelled) {
                this.cancelled = true;
                cancelSources();
                if (getAndIncrement() == 0) {
                    clear(this.queue);
                }
            }
        }

        @Override // io.reactivex.disposables.Disposable
        public boolean isDisposed() {
            return this.cancelled;
        }

        void cancelSources() {
            for (CombinerObserver<T, R> s : this.observers) {
                s.dispose();
            }
        }

        void clear(SpscLinkedArrayQueue<?> q) {
            synchronized (this) {
                this.latest = null;
            }
            q.clear();
        }

        void drain() {
            if (getAndIncrement() != 0) {
                return;
            }
            SpscLinkedArrayQueue<Object[]> spscLinkedArrayQueue = this.queue;
            Observer<? super R> observer = this.actual;
            boolean z = this.delayError;
            int iAddAndGet = 1;
            while (!this.cancelled) {
                if (!z && this.errors.get() != null) {
                    cancelSources();
                    clear(spscLinkedArrayQueue);
                    observer.onError(this.errors.terminate());
                    return;
                }
                boolean z2 = this.done;
                Object[] objArrPoll = spscLinkedArrayQueue.poll();
                boolean z3 = objArrPoll == null;
                if (z2 && z3) {
                    clear(spscLinkedArrayQueue);
                    Throwable thTerminate = this.errors.terminate();
                    if (thTerminate == null) {
                        observer.onComplete();
                        return;
                    } else {
                        observer.onError(thTerminate);
                        return;
                    }
                }
                if (!z3) {
                    try {
                        observer.onNext((Object) ObjectHelper.requireNonNull(this.combiner.apply(objArrPoll), "The combiner returned a null value"));
                    } catch (Throwable th) {
                        Exceptions.throwIfFatal(th);
                        this.errors.addThrowable(th);
                        cancelSources();
                        clear(spscLinkedArrayQueue);
                        observer.onError(this.errors.terminate());
                        return;
                    }
                } else {
                    iAddAndGet = addAndGet(-iAddAndGet);
                    if (iAddAndGet == 0) {
                        return;
                    }
                }
            }
            clear(spscLinkedArrayQueue);
        }

        void innerNext(int i, T t) {
            boolean z = false;
            synchronized (this) {
                Object[] objArr = this.latest;
                if (objArr == null) {
                    return;
                }
                Object obj = objArr[i];
                int i2 = this.active;
                if (obj == null) {
                    i2++;
                    this.active = i2;
                }
                objArr[i] = t;
                if (i2 == objArr.length) {
                    this.queue.offer((Object[]) objArr.clone());
                    z = true;
                }
                if (z) {
                    drain();
                }
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:19:0x0027 A[Catch: all -> 0x002b, TryCatch #0 {, blocks: (B:7:0x000e, B:9:0x0012, B:11:0x0014, B:17:0x001f, B:20:0x0029, B:19:0x0027), top: B:30:0x000e }] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        void innerError(int r6, java.lang.Throwable r7) {
            /*
                r5 = this;
                io.reactivex.internal.util.AtomicThrowable r0 = r5.errors
                boolean r0 = r0.addThrowable(r7)
                if (r0 == 0) goto L37
                r0 = 1
                boolean r1 = r5.delayError
                if (r1 == 0) goto L2e
                monitor-enter(r5)
                java.lang.Object[] r1 = r5.latest     // Catch: java.lang.Throwable -> L2b
                if (r1 != 0) goto L14
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L2b
                return
            L14:
                r2 = r1[r6]     // Catch: java.lang.Throwable -> L2b
                r3 = 1
                if (r2 != 0) goto L1b
                r2 = 1
                goto L1c
            L1b:
                r2 = 0
            L1c:
                r0 = r2
                if (r0 != 0) goto L27
                int r2 = r5.complete     // Catch: java.lang.Throwable -> L2b
                int r2 = r2 + r3
                r5.complete = r2     // Catch: java.lang.Throwable -> L2b
                int r4 = r1.length     // Catch: java.lang.Throwable -> L2b
                if (r2 != r4) goto L29
            L27:
                r5.done = r3     // Catch: java.lang.Throwable -> L2b
            L29:
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L2b
                goto L2e
            L2b:
                r1 = move-exception
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L2b
                throw r1
            L2e:
                if (r0 == 0) goto L33
                r5.cancelSources()
            L33:
                r5.drain()
                goto L3a
            L37:
                io.reactivex.plugins.RxJavaPlugins.onError(r7)
            L3a:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: io.reactivex.internal.operators.observable.ObservableCombineLatest.LatestCoordinator.innerError(int, java.lang.Throwable):void");
        }

        /* JADX WARN: Removed duplicated region for block: B:16:0x001b A[Catch: all -> 0x0027, TryCatch #0 {, blocks: (B:4:0x0002, B:6:0x0006, B:8:0x0008, B:14:0x0013, B:17:0x001d, B:16:0x001b), top: B:25:0x0002 }] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        void innerComplete(int r6) {
            /*
                r5 = this;
                r0 = 0
                monitor-enter(r5)
                java.lang.Object[] r1 = r5.latest     // Catch: java.lang.Throwable -> L27
                if (r1 != 0) goto L8
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L27
                return
            L8:
                r2 = r1[r6]     // Catch: java.lang.Throwable -> L27
                r3 = 1
                if (r2 != 0) goto Lf
                r2 = 1
                goto L10
            Lf:
                r2 = 0
            L10:
                r0 = r2
                if (r0 != 0) goto L1b
                int r2 = r5.complete     // Catch: java.lang.Throwable -> L27
                int r2 = r2 + r3
                r5.complete = r2     // Catch: java.lang.Throwable -> L27
                int r4 = r1.length     // Catch: java.lang.Throwable -> L27
                if (r2 != r4) goto L1d
            L1b:
                r5.done = r3     // Catch: java.lang.Throwable -> L27
            L1d:
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L27
                if (r0 == 0) goto L23
                r5.cancelSources()
            L23:
                r5.drain()
                return
            L27:
                r1 = move-exception
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L27
                throw r1
            */
            throw new UnsupportedOperationException("Method not decompiled: io.reactivex.internal.operators.observable.ObservableCombineLatest.LatestCoordinator.innerComplete(int):void");
        }
    }

    static final class CombinerObserver<T, R> extends AtomicReference<Disposable> implements Observer<T> {
        private static final long serialVersionUID = -4823716997131257941L;
        final int index;
        final LatestCoordinator<T, R> parent;

        CombinerObserver(LatestCoordinator<T, R> parent, int index) {
            this.parent = parent;
            this.index = index;
        }

        @Override // io.reactivex.Observer
        public void onSubscribe(Disposable s) {
            DisposableHelper.setOnce(this, s);
        }

        @Override // io.reactivex.Observer
        public void onNext(T t) {
            this.parent.innerNext(this.index, t);
        }

        @Override // io.reactivex.Observer
        public void onError(Throwable t) {
            this.parent.innerError(this.index, t);
        }

        @Override // io.reactivex.Observer
        public void onComplete() {
            this.parent.innerComplete(this.index);
        }

        public void dispose() {
            DisposableHelper.dispose(this);
        }
    }
}
