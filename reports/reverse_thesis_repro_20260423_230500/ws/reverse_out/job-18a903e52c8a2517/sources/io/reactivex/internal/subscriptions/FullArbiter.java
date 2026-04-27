package io.reactivex.internal.subscriptions;

import io.reactivex.disposables.Disposable;
import io.reactivex.internal.functions.ObjectHelper;
import io.reactivex.internal.queue.SpscLinkedArrayQueue;
import io.reactivex.internal.util.BackpressureHelper;
import io.reactivex.internal.util.NotificationLite;
import io.reactivex.plugins.RxJavaPlugins;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/* JADX INFO: loaded from: classes3.dex */
public final class FullArbiter<T> extends FullArbiterPad2 implements Subscription {
    static final Subscription INITIAL = new InitialSubscription();
    static final Object REQUEST = new Object();
    final Subscriber<? super T> actual;
    volatile boolean cancelled;
    final SpscLinkedArrayQueue<Object> queue;
    long requested;
    Disposable resource;
    volatile Subscription s = INITIAL;

    public FullArbiter(Subscriber<? super T> actual, Disposable resource, int capacity) {
        this.actual = actual;
        this.resource = resource;
        this.queue = new SpscLinkedArrayQueue<>(capacity);
    }

    @Override // org.reactivestreams.Subscription
    public void request(long n) {
        if (SubscriptionHelper.validate(n)) {
            BackpressureHelper.add(this.missedRequested, n);
            SpscLinkedArrayQueue<Object> spscLinkedArrayQueue = this.queue;
            Object obj = REQUEST;
            spscLinkedArrayQueue.offer(obj, obj);
            drain();
        }
    }

    @Override // org.reactivestreams.Subscription
    public void cancel() {
        if (!this.cancelled) {
            this.cancelled = true;
            dispose();
        }
    }

    void dispose() {
        Disposable d = this.resource;
        this.resource = null;
        if (d != null) {
            d.dispose();
        }
    }

    public boolean setSubscription(Subscription s) {
        if (this.cancelled) {
            if (s != null) {
                s.cancel();
                return false;
            }
            return false;
        }
        ObjectHelper.requireNonNull(s, "s is null");
        this.queue.offer(this.s, NotificationLite.subscription(s));
        drain();
        return true;
    }

    public boolean onNext(T value, Subscription s) {
        if (this.cancelled) {
            return false;
        }
        this.queue.offer(s, NotificationLite.next(value));
        drain();
        return true;
    }

    public void onError(Throwable value, Subscription s) {
        if (this.cancelled) {
            RxJavaPlugins.onError(value);
        } else {
            this.queue.offer(s, NotificationLite.error(value));
            drain();
        }
    }

    public void onComplete(Subscription s) {
        this.queue.offer(s, NotificationLite.complete());
        drain();
    }

    void drain() {
        if (this.wip.getAndIncrement() != 0) {
            return;
        }
        int iAddAndGet = 1;
        SpscLinkedArrayQueue<Object> spscLinkedArrayQueue = this.queue;
        Subscriber<? super T> subscriber = this.actual;
        while (true) {
            Object objPoll = spscLinkedArrayQueue.poll();
            if (objPoll != null) {
                Object objPoll2 = spscLinkedArrayQueue.poll();
                if (objPoll == REQUEST) {
                    long andSet = this.missedRequested.getAndSet(0L);
                    if (andSet != 0) {
                        this.requested = BackpressureHelper.addCap(this.requested, andSet);
                        this.s.request(andSet);
                    }
                } else if (objPoll == this.s) {
                    if (NotificationLite.isSubscription(objPoll2)) {
                        Subscription subscription = NotificationLite.getSubscription(objPoll2);
                        if (!this.cancelled) {
                            this.s = subscription;
                            long j = this.requested;
                            if (j != 0) {
                                subscription.request(j);
                            }
                        } else {
                            subscription.cancel();
                        }
                    } else if (NotificationLite.isError(objPoll2)) {
                        spscLinkedArrayQueue.clear();
                        dispose();
                        Throwable error = NotificationLite.getError(objPoll2);
                        if (!this.cancelled) {
                            this.cancelled = true;
                            subscriber.onError(error);
                        } else {
                            RxJavaPlugins.onError(error);
                        }
                    } else if (NotificationLite.isComplete(objPoll2)) {
                        spscLinkedArrayQueue.clear();
                        dispose();
                        if (!this.cancelled) {
                            this.cancelled = true;
                            subscriber.onComplete();
                        }
                    } else {
                        long j2 = this.requested;
                        if (j2 != 0) {
                            subscriber.onNext((Object) NotificationLite.getValue(objPoll2));
                            this.requested = j2 - 1;
                        }
                    }
                }
            } else {
                iAddAndGet = this.wip.addAndGet(-iAddAndGet);
                if (iAddAndGet == 0) {
                    return;
                }
            }
        }
    }

    static final class InitialSubscription implements Subscription {
        InitialSubscription() {
        }

        @Override // org.reactivestreams.Subscription
        public void request(long n) {
        }

        @Override // org.reactivestreams.Subscription
        public void cancel() {
        }
    }
}
