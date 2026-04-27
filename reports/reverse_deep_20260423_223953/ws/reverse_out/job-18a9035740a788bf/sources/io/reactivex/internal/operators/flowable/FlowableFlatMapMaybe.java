package io.reactivex.internal.operators.flowable;

import io.reactivex.Flowable;
import io.reactivex.FlowableSubscriber;
import io.reactivex.MaybeObserver;
import io.reactivex.MaybeSource;
import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.disposables.Disposable;
import io.reactivex.exceptions.Exceptions;
import io.reactivex.functions.Function;
import io.reactivex.internal.disposables.DisposableHelper;
import io.reactivex.internal.functions.ObjectHelper;
import io.reactivex.internal.queue.SpscLinkedArrayQueue;
import io.reactivex.internal.subscriptions.SubscriptionHelper;
import io.reactivex.internal.util.AtomicThrowable;
import io.reactivex.internal.util.BackpressureHelper;
import io.reactivex.plugins.RxJavaPlugins;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/* JADX INFO: loaded from: classes3.dex */
public final class FlowableFlatMapMaybe<T, R> extends AbstractFlowableWithUpstream<T, R> {
    final boolean delayErrors;
    final Function<? super T, ? extends MaybeSource<? extends R>> mapper;
    final int maxConcurrency;

    public FlowableFlatMapMaybe(Flowable<T> source, Function<? super T, ? extends MaybeSource<? extends R>> mapper, boolean delayError, int maxConcurrency) {
        super(source);
        this.mapper = mapper;
        this.delayErrors = delayError;
        this.maxConcurrency = maxConcurrency;
    }

    @Override // io.reactivex.Flowable
    protected void subscribeActual(Subscriber<? super R> s) {
        this.source.subscribe((FlowableSubscriber) new FlatMapMaybeSubscriber(s, this.mapper, this.delayErrors, this.maxConcurrency));
    }

    static final class FlatMapMaybeSubscriber<T, R> extends AtomicInteger implements FlowableSubscriber<T>, Subscription {
        private static final long serialVersionUID = 8600231336733376951L;
        final Subscriber<? super R> actual;
        volatile boolean cancelled;
        final boolean delayErrors;
        final Function<? super T, ? extends MaybeSource<? extends R>> mapper;
        final int maxConcurrency;
        Subscription s;
        final AtomicLong requested = new AtomicLong();
        final CompositeDisposable set = new CompositeDisposable();
        final AtomicThrowable errors = new AtomicThrowable();
        final AtomicInteger active = new AtomicInteger(1);
        final AtomicReference<SpscLinkedArrayQueue<R>> queue = new AtomicReference<>();

        FlatMapMaybeSubscriber(Subscriber<? super R> actual, Function<? super T, ? extends MaybeSource<? extends R>> mapper, boolean delayErrors, int maxConcurrency) {
            this.actual = actual;
            this.mapper = mapper;
            this.delayErrors = delayErrors;
            this.maxConcurrency = maxConcurrency;
        }

        @Override // io.reactivex.FlowableSubscriber, org.reactivestreams.Subscriber
        public void onSubscribe(Subscription s) {
            if (SubscriptionHelper.validate(this.s, s)) {
                this.s = s;
                this.actual.onSubscribe(this);
                int m = this.maxConcurrency;
                if (m == Integer.MAX_VALUE) {
                    s.request(Long.MAX_VALUE);
                } else {
                    s.request(this.maxConcurrency);
                }
            }
        }

        @Override // org.reactivestreams.Subscriber
        public void onNext(T t) {
            try {
                MaybeSource<? extends R> ms = (MaybeSource) ObjectHelper.requireNonNull(this.mapper.apply(t), "The mapper returned a null MaybeSource");
                this.active.getAndIncrement();
                FlatMapMaybeSubscriber<T, R>.InnerObserver inner = new InnerObserver();
                if (!this.cancelled && this.set.add(inner)) {
                    ms.subscribe(inner);
                }
            } catch (Throwable ex) {
                Exceptions.throwIfFatal(ex);
                this.s.cancel();
                onError(ex);
            }
        }

        @Override // org.reactivestreams.Subscriber
        public void onError(Throwable t) {
            this.active.decrementAndGet();
            if (this.errors.addThrowable(t)) {
                if (!this.delayErrors) {
                    this.set.dispose();
                }
                drain();
                return;
            }
            RxJavaPlugins.onError(t);
        }

        @Override // org.reactivestreams.Subscriber
        public void onComplete() {
            this.active.decrementAndGet();
            drain();
        }

        @Override // org.reactivestreams.Subscription
        public void cancel() {
            this.cancelled = true;
            this.s.cancel();
            this.set.dispose();
        }

        @Override // org.reactivestreams.Subscription
        public void request(long n) {
            if (SubscriptionHelper.validate(n)) {
                BackpressureHelper.add(this.requested, n);
                drain();
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:37:0x007c  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        void innerSuccess(io.reactivex.internal.operators.flowable.FlowableFlatMapMaybe.FlatMapMaybeSubscriber<T, R>.InnerObserver r7, R r8) {
            /*
                r6 = this;
                io.reactivex.disposables.CompositeDisposable r0 = r6.set
                r0.delete(r7)
                int r0 = r6.get()
                if (r0 != 0) goto L7c
                r0 = 1
                r1 = 0
                boolean r2 = r6.compareAndSet(r1, r0)
                if (r2 == 0) goto L7c
                java.util.concurrent.atomic.AtomicInteger r2 = r6.active
                int r2 = r2.decrementAndGet()
                if (r2 != 0) goto L1c
                goto L1d
            L1c:
                r0 = 0
            L1d:
                java.util.concurrent.atomic.AtomicLong r1 = r6.requested
                long r1 = r1.get()
                r3 = 0
                int r5 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
                if (r5 == 0) goto L68
                org.reactivestreams.Subscriber<? super R> r1 = r6.actual
                r1.onNext(r8)
                java.util.concurrent.atomic.AtomicReference<io.reactivex.internal.queue.SpscLinkedArrayQueue<R>> r1 = r6.queue
                java.lang.Object r1 = r1.get()
                io.reactivex.internal.queue.SpscLinkedArrayQueue r1 = (io.reactivex.internal.queue.SpscLinkedArrayQueue) r1
                if (r0 == 0) goto L54
                if (r1 == 0) goto L40
                boolean r2 = r1.isEmpty()
                if (r2 == 0) goto L54
            L40:
                io.reactivex.internal.util.AtomicThrowable r2 = r6.errors
                java.lang.Throwable r2 = r2.terminate()
                if (r2 == 0) goto L4e
                org.reactivestreams.Subscriber<? super R> r3 = r6.actual
                r3.onError(r2)
                goto L53
            L4e:
                org.reactivestreams.Subscriber<? super R> r3 = r6.actual
                r3.onComplete()
            L53:
                return
            L54:
                java.util.concurrent.atomic.AtomicLong r2 = r6.requested
                r3 = 1
                io.reactivex.internal.util.BackpressureHelper.produced(r2, r3)
                int r2 = r6.maxConcurrency
                r5 = 2147483647(0x7fffffff, float:NaN)
                if (r2 == r5) goto L67
                org.reactivestreams.Subscription r2 = r6.s
                r2.request(r3)
            L67:
                goto L71
            L68:
                io.reactivex.internal.queue.SpscLinkedArrayQueue r1 = r6.getOrCreateQueue()
                monitor-enter(r1)
                r1.offer(r8)     // Catch: java.lang.Throwable -> L79
                monitor-exit(r1)     // Catch: java.lang.Throwable -> L79
            L71:
                int r1 = r6.decrementAndGet()
                if (r1 != 0) goto L78
                return
            L78:
                goto L91
            L79:
                r2 = move-exception
                monitor-exit(r1)     // Catch: java.lang.Throwable -> L79
                throw r2
            L7c:
                io.reactivex.internal.queue.SpscLinkedArrayQueue r0 = r6.getOrCreateQueue()
                monitor-enter(r0)
                r0.offer(r8)     // Catch: java.lang.Throwable -> L95
                monitor-exit(r0)     // Catch: java.lang.Throwable -> L95
                java.util.concurrent.atomic.AtomicInteger r1 = r6.active
                r1.decrementAndGet()
                int r1 = r6.getAndIncrement()
                if (r1 == 0) goto L91
                return
            L91:
                r6.drainLoop()
                return
            L95:
                r1 = move-exception
                monitor-exit(r0)     // Catch: java.lang.Throwable -> L95
                throw r1
            */
            throw new UnsupportedOperationException("Method not decompiled: io.reactivex.internal.operators.flowable.FlowableFlatMapMaybe.FlatMapMaybeSubscriber.innerSuccess(io.reactivex.internal.operators.flowable.FlowableFlatMapMaybe$FlatMapMaybeSubscriber$InnerObserver, java.lang.Object):void");
        }

        SpscLinkedArrayQueue<R> getOrCreateQueue() {
            SpscLinkedArrayQueue<R> current;
            do {
                SpscLinkedArrayQueue<R> current2 = this.queue.get();
                if (current2 != null) {
                    return current2;
                }
                current = new SpscLinkedArrayQueue<>(Flowable.bufferSize());
            } while (!this.queue.compareAndSet(null, current));
            return current;
        }

        void innerError(FlatMapMaybeSubscriber<T, R>.InnerObserver inner, Throwable e) {
            this.set.delete(inner);
            if (this.errors.addThrowable(e)) {
                if (!this.delayErrors) {
                    this.s.cancel();
                    this.set.dispose();
                } else if (this.maxConcurrency != Integer.MAX_VALUE) {
                    this.s.request(1L);
                }
                this.active.decrementAndGet();
                drain();
                return;
            }
            RxJavaPlugins.onError(e);
        }

        void innerComplete(FlatMapMaybeSubscriber<T, R>.InnerObserver inner) {
            this.set.delete(inner);
            if (get() == 0) {
                if (compareAndSet(0, 1)) {
                    boolean d = this.active.decrementAndGet() == 0;
                    SpscLinkedArrayQueue<R> q = this.queue.get();
                    if (d && (q == null || q.isEmpty())) {
                        Throwable ex = this.errors.terminate();
                        if (ex != null) {
                            this.actual.onError(ex);
                            return;
                        } else {
                            this.actual.onComplete();
                            return;
                        }
                    }
                    if (this.maxConcurrency != Integer.MAX_VALUE) {
                        this.s.request(1L);
                    }
                    if (decrementAndGet() == 0) {
                        return;
                    }
                    drainLoop();
                    return;
                }
            }
            this.active.decrementAndGet();
            if (this.maxConcurrency != Integer.MAX_VALUE) {
                this.s.request(1L);
            }
            drain();
        }

        void drain() {
            if (getAndIncrement() == 0) {
                drainLoop();
            }
        }

        void clear() {
            SpscLinkedArrayQueue<R> q = this.queue.get();
            if (q != null) {
                q.clear();
            }
        }

        /* JADX WARN: Code restructure failed: missing block: B:38:0x0074, code lost:
        
            if (r6 != r4) goto L66;
         */
        /* JADX WARN: Code restructure failed: missing block: B:40:0x0078, code lost:
        
            if (r14.cancelled == false) goto L43;
         */
        /* JADX WARN: Code restructure failed: missing block: B:41:0x007a, code lost:
        
            clear();
         */
        /* JADX WARN: Code restructure failed: missing block: B:42:0x007d, code lost:
        
            return;
         */
        /* JADX WARN: Code restructure failed: missing block: B:44:0x0080, code lost:
        
            if (r14.delayErrors != false) goto L49;
         */
        /* JADX WARN: Code restructure failed: missing block: B:46:0x008a, code lost:
        
            if (r14.errors.get() == null) goto L49;
         */
        /* JADX WARN: Code restructure failed: missing block: B:47:0x008c, code lost:
        
            r8 = r14.errors.terminate();
            clear();
            r1.onError(r8);
         */
        /* JADX WARN: Code restructure failed: missing block: B:48:0x0098, code lost:
        
            return;
         */
        /* JADX WARN: Code restructure failed: missing block: B:50:0x009d, code lost:
        
            if (r2.get() != 0) goto L52;
         */
        /* JADX WARN: Code restructure failed: missing block: B:51:0x009f, code lost:
        
            r10 = true;
         */
        /* JADX WARN: Code restructure failed: missing block: B:52:0x00a1, code lost:
        
            r10 = false;
         */
        /* JADX WARN: Code restructure failed: missing block: B:53:0x00a2, code lost:
        
            r11 = r3.get();
         */
        /* JADX WARN: Code restructure failed: missing block: B:54:0x00a8, code lost:
        
            if (r11 == null) goto L59;
         */
        /* JADX WARN: Code restructure failed: missing block: B:56:0x00ae, code lost:
        
            if (r11.isEmpty() == false) goto L58;
         */
        /* JADX WARN: Code restructure failed: missing block: B:58:0x00b1, code lost:
        
            r8 = false;
         */
        /* JADX WARN: Code restructure failed: missing block: B:59:0x00b2, code lost:
        
            if (r10 == false) goto L66;
         */
        /* JADX WARN: Code restructure failed: missing block: B:60:0x00b4, code lost:
        
            if (r8 == false) goto L66;
         */
        /* JADX WARN: Code restructure failed: missing block: B:61:0x00b6, code lost:
        
            r9 = r14.errors.terminate();
         */
        /* JADX WARN: Code restructure failed: missing block: B:62:0x00bc, code lost:
        
            if (r9 == null) goto L64;
         */
        /* JADX WARN: Code restructure failed: missing block: B:63:0x00be, code lost:
        
            r1.onError(r9);
         */
        /* JADX WARN: Code restructure failed: missing block: B:64:0x00c2, code lost:
        
            r1.onComplete();
         */
        /* JADX WARN: Code restructure failed: missing block: B:65:0x00c5, code lost:
        
            return;
         */
        /* JADX WARN: Code restructure failed: missing block: B:67:0x00ca, code lost:
        
            if (r6 == 0) goto L71;
         */
        /* JADX WARN: Code restructure failed: missing block: B:68:0x00cc, code lost:
        
            io.reactivex.internal.util.BackpressureHelper.produced(r14.requested, r6);
         */
        /* JADX WARN: Code restructure failed: missing block: B:69:0x00d6, code lost:
        
            if (r14.maxConcurrency == Integer.MAX_VALUE) goto L71;
         */
        /* JADX WARN: Code restructure failed: missing block: B:70:0x00d8, code lost:
        
            r14.s.request(r6);
         */
        /* JADX WARN: Code restructure failed: missing block: B:71:0x00dd, code lost:
        
            r0 = addAndGet(-r0);
         */
        /* JADX WARN: Code restructure failed: missing block: B:86:?, code lost:
        
            return;
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        void drainLoop() {
            /*
                Method dump skipped, instruction units count: 232
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: io.reactivex.internal.operators.flowable.FlowableFlatMapMaybe.FlatMapMaybeSubscriber.drainLoop():void");
        }

        final class InnerObserver extends AtomicReference<Disposable> implements MaybeObserver<R>, Disposable {
            private static final long serialVersionUID = -502562646270949838L;

            InnerObserver() {
            }

            @Override // io.reactivex.MaybeObserver
            public void onSubscribe(Disposable d) {
                DisposableHelper.setOnce(this, d);
            }

            @Override // io.reactivex.MaybeObserver
            public void onSuccess(R value) {
                FlatMapMaybeSubscriber.this.innerSuccess(this, value);
            }

            @Override // io.reactivex.MaybeObserver
            public void onError(Throwable e) {
                FlatMapMaybeSubscriber.this.innerError(this, e);
            }

            @Override // io.reactivex.MaybeObserver
            public void onComplete() {
                FlatMapMaybeSubscriber.this.innerComplete(this);
            }

            @Override // io.reactivex.disposables.Disposable
            public boolean isDisposed() {
                return DisposableHelper.isDisposed(get());
            }

            @Override // io.reactivex.disposables.Disposable
            public void dispose() {
                DisposableHelper.dispose(this);
            }
        }
    }
}
