package io.reactivex.internal.operators.flowable;

import io.reactivex.Flowable;
import io.reactivex.FlowableSubscriber;
import io.reactivex.internal.subscriptions.SubscriptionHelper;
import io.reactivex.internal.util.BackpressureHelper;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/* JADX INFO: loaded from: classes3.dex */
public final class FlowableOnBackpressureLatest<T> extends AbstractFlowableWithUpstream<T, T> {
    public FlowableOnBackpressureLatest(Flowable<T> source) {
        super(source);
    }

    @Override // io.reactivex.Flowable
    protected void subscribeActual(Subscriber<? super T> s) {
        this.source.subscribe((FlowableSubscriber) new BackpressureLatestSubscriber(s));
    }

    static final class BackpressureLatestSubscriber<T> extends AtomicInteger implements FlowableSubscriber<T>, Subscription {
        private static final long serialVersionUID = 163080509307634843L;
        final Subscriber<? super T> actual;
        volatile boolean cancelled;
        volatile boolean done;
        Throwable error;
        Subscription s;
        final AtomicLong requested = new AtomicLong();
        final AtomicReference<T> current = new AtomicReference<>();

        BackpressureLatestSubscriber(Subscriber<? super T> actual) {
            this.actual = actual;
        }

        @Override // io.reactivex.FlowableSubscriber, org.reactivestreams.Subscriber
        public void onSubscribe(Subscription s) {
            if (SubscriptionHelper.validate(this.s, s)) {
                this.s = s;
                this.actual.onSubscribe(this);
                s.request(Long.MAX_VALUE);
            }
        }

        @Override // org.reactivestreams.Subscriber
        public void onNext(T t) {
            this.current.lazySet(t);
            drain();
        }

        @Override // org.reactivestreams.Subscriber
        public void onError(Throwable t) {
            this.error = t;
            this.done = true;
            drain();
        }

        @Override // org.reactivestreams.Subscriber
        public void onComplete() {
            this.done = true;
            drain();
        }

        @Override // org.reactivestreams.Subscription
        public void request(long n) {
            if (SubscriptionHelper.validate(n)) {
                BackpressureHelper.add(this.requested, n);
                drain();
            }
        }

        @Override // org.reactivestreams.Subscription
        public void cancel() {
            if (!this.cancelled) {
                this.cancelled = true;
                this.s.cancel();
                if (getAndIncrement() == 0) {
                    this.current.lazySet(null);
                }
            }
        }

        /* JADX WARN: Code restructure failed: missing block: B:20:0x003d, code lost:
        
            if (r4 != r2.get()) goto L28;
         */
        /* JADX WARN: Code restructure failed: missing block: B:21:0x003f, code lost:
        
            r6 = r12.done;
         */
        /* JADX WARN: Code restructure failed: missing block: B:22:0x0045, code lost:
        
            if (r3.get() != null) goto L24;
         */
        /* JADX WARN: Code restructure failed: missing block: B:24:0x0048, code lost:
        
            r8 = false;
         */
        /* JADX WARN: Code restructure failed: missing block: B:26:0x004d, code lost:
        
            if (checkTerminated(r6, r8, r0, r3) == false) goto L28;
         */
        /* JADX WARN: Code restructure failed: missing block: B:27:0x004f, code lost:
        
            return;
         */
        /* JADX WARN: Code restructure failed: missing block: B:29:0x0054, code lost:
        
            if (r4 == 0) goto L31;
         */
        /* JADX WARN: Code restructure failed: missing block: B:30:0x0056, code lost:
        
            io.reactivex.internal.util.BackpressureHelper.produced(r2, r4);
         */
        /* JADX WARN: Code restructure failed: missing block: B:31:0x0059, code lost:
        
            r1 = addAndGet(-r1);
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        void drain() {
            /*
                r12 = this;
                int r0 = r12.getAndIncrement()
                if (r0 == 0) goto L7
                return
            L7:
                org.reactivestreams.Subscriber<? super T> r0 = r12.actual
                r1 = 1
                java.util.concurrent.atomic.AtomicLong r2 = r12.requested
                java.util.concurrent.atomic.AtomicReference<T> r3 = r12.current
            Le:
                r4 = 0
            L10:
                long r6 = r2.get()
                r8 = 1
                r9 = 0
                int r10 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
                if (r10 == 0) goto L37
                boolean r6 = r12.done
                r7 = 0
                java.lang.Object r7 = r3.getAndSet(r7)
                if (r7 != 0) goto L25
                r10 = 1
                goto L26
            L25:
                r10 = 0
            L26:
                boolean r11 = r12.checkTerminated(r6, r10, r0, r3)
                if (r11 == 0) goto L2d
                return
            L2d:
                if (r10 == 0) goto L30
                goto L37
            L30:
                r0.onNext(r7)
                r8 = 1
                long r4 = r4 + r8
                goto L10
            L37:
                long r6 = r2.get()
                int r10 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
                if (r10 != 0) goto L50
                boolean r6 = r12.done
                java.lang.Object r7 = r3.get()
                if (r7 != 0) goto L48
                goto L49
            L48:
                r8 = 0
            L49:
                boolean r6 = r12.checkTerminated(r6, r8, r0, r3)
                if (r6 == 0) goto L50
                return
            L50:
                r6 = 0
                int r8 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
                if (r8 == 0) goto L59
                io.reactivex.internal.util.BackpressureHelper.produced(r2, r4)
            L59:
                int r6 = -r1
                int r1 = r12.addAndGet(r6)
                if (r1 != 0) goto L62
            L61:
                return
            L62:
                goto Le
            */
            throw new UnsupportedOperationException("Method not decompiled: io.reactivex.internal.operators.flowable.FlowableOnBackpressureLatest.BackpressureLatestSubscriber.drain():void");
        }

        boolean checkTerminated(boolean d, boolean empty, Subscriber<?> a, AtomicReference<T> q) {
            if (this.cancelled) {
                q.lazySet(null);
                return true;
            }
            if (d) {
                Throwable e = this.error;
                if (e != null) {
                    q.lazySet(null);
                    a.onError(e);
                    return true;
                }
                if (empty) {
                    a.onComplete();
                    return true;
                }
                return false;
            }
            return false;
        }
    }
}
