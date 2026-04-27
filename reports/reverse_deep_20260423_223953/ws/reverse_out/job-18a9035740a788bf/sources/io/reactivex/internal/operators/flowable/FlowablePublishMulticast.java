package io.reactivex.internal.operators.flowable;

import io.reactivex.Flowable;
import io.reactivex.FlowableSubscriber;
import io.reactivex.disposables.Disposable;
import io.reactivex.exceptions.Exceptions;
import io.reactivex.exceptions.MissingBackpressureException;
import io.reactivex.functions.Function;
import io.reactivex.internal.functions.ObjectHelper;
import io.reactivex.internal.fuseable.QueueSubscription;
import io.reactivex.internal.fuseable.SimpleQueue;
import io.reactivex.internal.subscriptions.EmptySubscription;
import io.reactivex.internal.subscriptions.SubscriptionHelper;
import io.reactivex.internal.util.BackpressureHelper;
import io.reactivex.internal.util.QueueDrainHelper;
import io.reactivex.plugins.RxJavaPlugins;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/* JADX INFO: loaded from: classes3.dex */
public final class FlowablePublishMulticast<T, R> extends AbstractFlowableWithUpstream<T, R> {
    final boolean delayError;
    final int prefetch;
    final Function<? super Flowable<T>, ? extends Publisher<? extends R>> selector;

    public FlowablePublishMulticast(Flowable<T> source, Function<? super Flowable<T>, ? extends Publisher<? extends R>> selector, int prefetch, boolean delayError) {
        super(source);
        this.selector = selector;
        this.prefetch = prefetch;
        this.delayError = delayError;
    }

    @Override // io.reactivex.Flowable
    protected void subscribeActual(Subscriber<? super R> s) {
        MulticastProcessor<T> mp = new MulticastProcessor<>(this.prefetch, this.delayError);
        try {
            Publisher<? extends R> other = (Publisher) ObjectHelper.requireNonNull(this.selector.apply(mp), "selector returned a null Publisher");
            OutputCanceller<R> out = new OutputCanceller<>(s, mp);
            other.subscribe(out);
            this.source.subscribe((FlowableSubscriber) mp);
        } catch (Throwable ex) {
            Exceptions.throwIfFatal(ex);
            EmptySubscription.error(ex, s);
        }
    }

    static final class OutputCanceller<R> implements FlowableSubscriber<R>, Subscription {
        final Subscriber<? super R> actual;
        final MulticastProcessor<?> processor;
        Subscription s;

        OutputCanceller(Subscriber<? super R> actual, MulticastProcessor<?> processor) {
            this.actual = actual;
            this.processor = processor;
        }

        @Override // io.reactivex.FlowableSubscriber, org.reactivestreams.Subscriber
        public void onSubscribe(Subscription s) {
            if (SubscriptionHelper.validate(this.s, s)) {
                this.s = s;
                this.actual.onSubscribe(this);
            }
        }

        @Override // org.reactivestreams.Subscriber
        public void onNext(R t) {
            this.actual.onNext(t);
        }

        @Override // org.reactivestreams.Subscriber
        public void onError(Throwable t) {
            this.actual.onError(t);
            this.processor.dispose();
        }

        @Override // org.reactivestreams.Subscriber
        public void onComplete() {
            this.actual.onComplete();
            this.processor.dispose();
        }

        @Override // org.reactivestreams.Subscription
        public void request(long n) {
            this.s.request(n);
        }

        @Override // org.reactivestreams.Subscription
        public void cancel() {
            this.s.cancel();
            this.processor.dispose();
        }
    }

    static final class MulticastProcessor<T> extends Flowable<T> implements FlowableSubscriber<T>, Disposable {
        static final MulticastSubscription[] EMPTY = new MulticastSubscription[0];
        static final MulticastSubscription[] TERMINATED = new MulticastSubscription[0];
        int consumed;
        final boolean delayError;
        volatile boolean done;
        Throwable error;
        final int limit;
        final int prefetch;
        volatile SimpleQueue<T> queue;
        int sourceMode;
        final AtomicInteger wip = new AtomicInteger();
        final AtomicReference<Subscription> s = new AtomicReference<>();
        final AtomicReference<MulticastSubscription<T>[]> subscribers = new AtomicReference<>(EMPTY);

        MulticastProcessor(int prefetch, boolean delayError) {
            this.prefetch = prefetch;
            this.limit = prefetch - (prefetch >> 2);
            this.delayError = delayError;
        }

        @Override // io.reactivex.FlowableSubscriber, org.reactivestreams.Subscriber
        public void onSubscribe(Subscription s) {
            if (SubscriptionHelper.setOnce(this.s, s)) {
                if (s instanceof QueueSubscription) {
                    QueueSubscription<T> qs = (QueueSubscription) s;
                    int m = qs.requestFusion(3);
                    if (m == 1) {
                        this.sourceMode = m;
                        this.queue = qs;
                        this.done = true;
                        drain();
                        return;
                    }
                    if (m == 2) {
                        this.sourceMode = m;
                        this.queue = qs;
                        QueueDrainHelper.request(s, this.prefetch);
                        return;
                    }
                }
                this.queue = QueueDrainHelper.createQueue(this.prefetch);
                QueueDrainHelper.request(s, this.prefetch);
            }
        }

        @Override // io.reactivex.disposables.Disposable
        public void dispose() {
            SimpleQueue<T> q;
            SubscriptionHelper.cancel(this.s);
            if (this.wip.getAndIncrement() == 0 && (q = this.queue) != null) {
                q.clear();
            }
        }

        @Override // io.reactivex.disposables.Disposable
        public boolean isDisposed() {
            return SubscriptionHelper.isCancelled(this.s.get());
        }

        @Override // org.reactivestreams.Subscriber
        public void onNext(T t) {
            if (this.done) {
                return;
            }
            if (this.sourceMode == 0 && !this.queue.offer(t)) {
                this.s.get().cancel();
                onError(new MissingBackpressureException());
            } else {
                drain();
            }
        }

        @Override // org.reactivestreams.Subscriber
        public void onError(Throwable t) {
            if (this.done) {
                RxJavaPlugins.onError(t);
                return;
            }
            this.error = t;
            this.done = true;
            drain();
        }

        @Override // org.reactivestreams.Subscriber
        public void onComplete() {
            if (!this.done) {
                this.done = true;
                drain();
            }
        }

        boolean add(MulticastSubscription<T> s) {
            MulticastSubscription<T>[] current;
            MulticastSubscription<T>[] next;
            do {
                current = this.subscribers.get();
                if (current == TERMINATED) {
                    return false;
                }
                int n = current.length;
                next = new MulticastSubscription[n + 1];
                System.arraycopy(current, 0, next, 0, n);
                next[n] = s;
            } while (!this.subscribers.compareAndSet(current, next));
            return true;
        }

        void remove(MulticastSubscription<T> s) {
            MulticastSubscription<T>[] current;
            MulticastSubscription<T>[] next;
            do {
                current = this.subscribers.get();
                if (current == TERMINATED || current == EMPTY) {
                    return;
                }
                int n = current.length;
                int j = -1;
                int i = 0;
                while (true) {
                    if (i >= n) {
                        break;
                    }
                    if (current[i] != s) {
                        i++;
                    } else {
                        j = i;
                        break;
                    }
                }
                if (j < 0) {
                    return;
                }
                if (n == 1) {
                    next = EMPTY;
                } else {
                    MulticastSubscription<T>[] next2 = new MulticastSubscription[n - 1];
                    System.arraycopy(current, 0, next2, 0, j);
                    System.arraycopy(current, j + 1, next2, j, (n - j) - 1);
                    next = next2;
                }
            } while (!this.subscribers.compareAndSet(current, next));
        }

        @Override // io.reactivex.Flowable
        protected void subscribeActual(Subscriber<? super T> s) {
            MulticastSubscription<T> ms = new MulticastSubscription<>(s, this);
            s.onSubscribe(ms);
            if (add(ms)) {
                if (ms.isCancelled()) {
                    remove(ms);
                    return;
                } else {
                    drain();
                    return;
                }
            }
            Throwable ex = this.error;
            if (ex != null) {
                s.onError(ex);
            } else {
                s.onComplete();
            }
        }

        void drain() {
            Throwable ex;
            boolean d;
            Throwable ex2;
            if (this.wip.getAndIncrement() != 0) {
                return;
            }
            SimpleQueue<T> q = this.queue;
            int upstreamConsumed = this.consumed;
            int localLimit = this.limit;
            boolean canRequest = this.sourceMode != 1;
            int missed = 1;
            int upstreamConsumed2 = upstreamConsumed;
            SimpleQueue<T> q2 = q;
            while (true) {
                MulticastSubscription<T>[] array = this.subscribers.get();
                int n = array.length;
                if (q2 != null && n != 0) {
                    long r = Long.MAX_VALUE;
                    for (MulticastSubscription<T> multicastSubscription : array) {
                        long u = multicastSubscription.get();
                        if (u != Long.MIN_VALUE && r > u) {
                            r = u;
                        }
                    }
                    long e = 0;
                    int upstreamConsumed3 = upstreamConsumed2;
                    while (e != r) {
                        if (isDisposed()) {
                            q2.clear();
                            return;
                        }
                        boolean d2 = this.done;
                        if (d2 && !this.delayError && (ex2 = this.error) != null) {
                            errorAll(ex2);
                            return;
                        }
                        try {
                            T v = q2.poll();
                            boolean empty = v == null;
                            if (d2 && empty) {
                                Throwable ex3 = this.error;
                                if (ex3 != null) {
                                    errorAll(ex3);
                                    return;
                                } else {
                                    completeAll();
                                    return;
                                }
                            }
                            if (empty) {
                                break;
                            }
                            int length = array.length;
                            int i = 0;
                            while (i < length) {
                                int n2 = n;
                                MulticastSubscription<T> ms = array[i];
                                if (ms.get() == Long.MIN_VALUE) {
                                    d = d2;
                                } else {
                                    d = d2;
                                    ms.actual.onNext(v);
                                }
                                i++;
                                n = n2;
                                d2 = d;
                            }
                            int n3 = n;
                            e++;
                            if (canRequest && (upstreamConsumed3 = upstreamConsumed3 + 1) == localLimit) {
                                this.s.get().request(localLimit);
                                upstreamConsumed3 = 0;
                            }
                            n = n3;
                        } catch (Throwable ex4) {
                            Exceptions.throwIfFatal(ex4);
                            SubscriptionHelper.cancel(this.s);
                            errorAll(ex4);
                            return;
                        }
                    }
                    if (e == r) {
                        if (isDisposed()) {
                            q2.clear();
                            return;
                        }
                        boolean d3 = this.done;
                        if (d3 && !this.delayError && (ex = this.error) != null) {
                            errorAll(ex);
                            return;
                        }
                        if (d3 && q2.isEmpty()) {
                            Throwable ex5 = this.error;
                            if (ex5 != null) {
                                errorAll(ex5);
                                return;
                            } else {
                                completeAll();
                                return;
                            }
                        }
                    }
                    for (MulticastSubscription<T> multicastSubscription2 : array) {
                        BackpressureHelper.produced(multicastSubscription2, e);
                    }
                    upstreamConsumed2 = upstreamConsumed3;
                }
                this.consumed = upstreamConsumed2;
                missed = this.wip.addAndGet(-missed);
                if (missed != 0) {
                    if (q2 == null) {
                        q2 = this.queue;
                    }
                } else {
                    return;
                }
            }
        }

        void errorAll(Throwable ex) {
            for (MulticastSubscription<T> ms : this.subscribers.getAndSet(TERMINATED)) {
                if (ms.get() != Long.MIN_VALUE) {
                    ms.actual.onError(ex);
                }
            }
        }

        void completeAll() {
            for (MulticastSubscription<T> ms : this.subscribers.getAndSet(TERMINATED)) {
                if (ms.get() != Long.MIN_VALUE) {
                    ms.actual.onComplete();
                }
            }
        }
    }

    static final class MulticastSubscription<T> extends AtomicLong implements Subscription {
        private static final long serialVersionUID = 8664815189257569791L;
        final Subscriber<? super T> actual;
        final MulticastProcessor<T> parent;

        MulticastSubscription(Subscriber<? super T> actual, MulticastProcessor<T> parent) {
            this.actual = actual;
            this.parent = parent;
        }

        @Override // org.reactivestreams.Subscription
        public void request(long n) {
            if (SubscriptionHelper.validate(n)) {
                BackpressureHelper.addCancel(this, n);
                this.parent.drain();
            }
        }

        @Override // org.reactivestreams.Subscription
        public void cancel() {
            if (getAndSet(Long.MIN_VALUE) != Long.MIN_VALUE) {
                this.parent.remove(this);
                this.parent.drain();
            }
        }

        public boolean isCancelled() {
            return get() == Long.MIN_VALUE;
        }
    }
}
