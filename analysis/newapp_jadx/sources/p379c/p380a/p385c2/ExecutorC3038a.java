package p379c.p380a.p385c2;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.LockSupport;
import kotlin.Unit;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.Random;
import kotlin.ranges.RangesKt___RangesKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2970s;

/* renamed from: c.a.c2.a */
/* loaded from: classes2.dex */
public final class ExecutorC3038a implements Executor, Closeable {
    public volatile int _isTerminated;
    public volatile long controlState;

    /* renamed from: h */
    @JvmField
    @NotNull
    public final C3041d f8349h;

    /* renamed from: i */
    @JvmField
    @NotNull
    public final C3041d f8350i;

    /* renamed from: j */
    @JvmField
    @NotNull
    public final AtomicReferenceArray<a> f8351j;

    /* renamed from: k */
    @JvmField
    public final int f8352k;

    /* renamed from: l */
    @JvmField
    public final int f8353l;

    /* renamed from: m */
    @JvmField
    public final long f8354m;

    /* renamed from: n */
    @JvmField
    @NotNull
    public final String f8355n;
    public volatile long parkedWorkersStack;

    /* renamed from: g */
    @JvmField
    @NotNull
    public static final C2970s f8348g = new C2970s("NOT_IN_STACK");

    /* renamed from: c */
    public static final AtomicLongFieldUpdater f8345c = AtomicLongFieldUpdater.newUpdater(ExecutorC3038a.class, "parkedWorkersStack");

    /* renamed from: e */
    public static final AtomicLongFieldUpdater f8346e = AtomicLongFieldUpdater.newUpdater(ExecutorC3038a.class, "controlState");

    /* renamed from: f */
    public static final AtomicIntegerFieldUpdater f8347f = AtomicIntegerFieldUpdater.newUpdater(ExecutorC3038a.class, "_isTerminated");

    /* renamed from: c.a.c2.a$a */
    public final class a extends Thread {

        /* renamed from: c */
        public static final AtomicIntegerFieldUpdater f8356c = AtomicIntegerFieldUpdater.newUpdater(a.class, "workerCtl");

        /* renamed from: e */
        @JvmField
        @NotNull
        public final C3050m f8357e;

        /* renamed from: f */
        @JvmField
        @NotNull
        public int f8358f;

        /* renamed from: g */
        public long f8359g;

        /* renamed from: h */
        public long f8360h;

        /* renamed from: i */
        public int f8361i;
        public volatile int indexInArray;

        /* renamed from: j */
        @JvmField
        public boolean f8362j;

        @Nullable
        public volatile Object nextParkedWorker;

        @NotNull
        public volatile int workerCtl;

        public a(int i2) {
            setDaemon(true);
            this.f8357e = new C3050m();
            this.f8358f = 4;
            this.workerCtl = 0;
            this.nextParkedWorker = ExecutorC3038a.f8348g;
            this.f8361i = Random.INSTANCE.nextInt();
            m3535d(i2);
        }

        /* JADX WARN: Removed duplicated region for block: B:14:0x0033  */
        /* JADX WARN: Removed duplicated region for block: B:35:0x006a  */
        @org.jetbrains.annotations.Nullable
        /* renamed from: a */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final p379c.p380a.p385c2.AbstractRunnableC3045h m3532a(boolean r10) {
            /*
                r9 = this;
                int r0 = r9.f8358f
                r1 = 0
                r2 = 1
                if (r0 != r2) goto L7
                goto L2e
            L7:
                c.a.c2.a r0 = p379c.p380a.p385c2.ExecutorC3038a.this
            L9:
                long r5 = r0.controlState
                r3 = 9223367638808264704(0x7ffffc0000000000, double:NaN)
                long r3 = r3 & r5
                r7 = 42
                long r3 = r3 >> r7
                int r4 = (int) r3
                if (r4 != 0) goto L19
                r0 = 0
                goto L2a
            L19:
                r3 = 4398046511104(0x40000000000, double:2.1729236899484E-311)
                long r7 = r5 - r3
                java.util.concurrent.atomic.AtomicLongFieldUpdater r3 = p379c.p380a.p385c2.ExecutorC3038a.f8346e
                r4 = r0
                boolean r3 = r3.compareAndSet(r4, r5, r7)
                if (r3 == 0) goto L9
                r0 = 1
            L2a:
                if (r0 == 0) goto L30
                r9.f8358f = r2
            L2e:
                r0 = 1
                goto L31
            L30:
                r0 = 0
            L31:
                if (r0 == 0) goto L6a
                if (r10 == 0) goto L5e
                c.a.c2.a r10 = p379c.p380a.p385c2.ExecutorC3038a.this
                int r10 = r10.f8352k
                int r10 = r10 * 2
                int r10 = r9.m3533b(r10)
                if (r10 != 0) goto L42
                goto L43
            L42:
                r2 = 0
            L43:
                if (r2 == 0) goto L4c
                c.a.c2.h r10 = r9.m3534c()
                if (r10 == 0) goto L4c
                goto L69
            L4c:
                c.a.c2.m r10 = r9.f8357e
                c.a.c2.h r10 = r10.m3546e()
                if (r10 == 0) goto L55
                goto L69
            L55:
                if (r2 != 0) goto L65
                c.a.c2.h r10 = r9.m3534c()
                if (r10 == 0) goto L65
                goto L69
            L5e:
                c.a.c2.h r10 = r9.m3534c()
                if (r10 == 0) goto L65
                goto L69
            L65:
                c.a.c2.h r10 = r9.m3537f(r1)
            L69:
                return r10
            L6a:
                if (r10 == 0) goto L80
                c.a.c2.m r10 = r9.f8357e
                c.a.c2.h r10 = r10.m3546e()
                if (r10 == 0) goto L75
                goto L8a
            L75:
                c.a.c2.a r10 = p379c.p380a.p385c2.ExecutorC3038a.this
                c.a.c2.d r10 = r10.f8350i
                java.lang.Object r10 = r10.m3437d()
                c.a.c2.h r10 = (p379c.p380a.p385c2.AbstractRunnableC3045h) r10
                goto L8a
            L80:
                c.a.c2.a r10 = p379c.p380a.p385c2.ExecutorC3038a.this
                c.a.c2.d r10 = r10.f8350i
                java.lang.Object r10 = r10.m3437d()
                c.a.c2.h r10 = (p379c.p380a.p385c2.AbstractRunnableC3045h) r10
            L8a:
                if (r10 == 0) goto L8d
                goto L91
            L8d:
                c.a.c2.h r10 = r9.m3537f(r2)
            L91:
                return r10
            */
            throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p385c2.ExecutorC3038a.a.m3532a(boolean):c.a.c2.h");
        }

        /* renamed from: b */
        public final int m3533b(int i2) {
            int i3 = this.f8361i;
            int i4 = i3 ^ (i3 << 13);
            int i5 = i4 ^ (i4 >> 17);
            int i6 = i5 ^ (i5 << 5);
            this.f8361i = i6;
            int i7 = i2 - 1;
            return (i7 & i2) == 0 ? i6 & i7 : (i6 & Integer.MAX_VALUE) % i2;
        }

        /* renamed from: c */
        public final AbstractRunnableC3045h m3534c() {
            if (m3533b(2) == 0) {
                AbstractRunnableC3045h m3437d = ExecutorC3038a.this.f8349h.m3437d();
                return m3437d != null ? m3437d : ExecutorC3038a.this.f8350i.m3437d();
            }
            AbstractRunnableC3045h m3437d2 = ExecutorC3038a.this.f8350i.m3437d();
            return m3437d2 != null ? m3437d2 : ExecutorC3038a.this.f8349h.m3437d();
        }

        /* renamed from: d */
        public final void m3535d(int i2) {
            StringBuilder sb = new StringBuilder();
            sb.append(ExecutorC3038a.this.f8355n);
            sb.append("-worker-");
            sb.append(i2 == 0 ? "TERMINATED" : String.valueOf(i2));
            setName(sb.toString());
            this.indexInArray = i2;
        }

        /* renamed from: e */
        public final boolean m3536e(@NotNull int i2) {
            int i3 = this.f8358f;
            boolean z = i3 == 1;
            if (z) {
                ExecutorC3038a.f8346e.addAndGet(ExecutorC3038a.this, 4398046511104L);
            }
            if (i3 != i2) {
                this.f8358f = i2;
            }
            return z;
        }

        /* renamed from: f */
        public final AbstractRunnableC3045h m3537f(boolean z) {
            long m3548g;
            int i2 = (int) (ExecutorC3038a.this.controlState & 2097151);
            if (i2 < 2) {
                return null;
            }
            int m3533b = m3533b(i2);
            long j2 = Long.MAX_VALUE;
            for (int i3 = 0; i3 < i2; i3++) {
                m3533b++;
                if (m3533b > i2) {
                    m3533b = 1;
                }
                a aVar = ExecutorC3038a.this.f8351j.get(m3533b);
                if (aVar != null && aVar != this) {
                    if (z) {
                        C3050m c3050m = this.f8357e;
                        C3050m c3050m2 = aVar.f8357e;
                        Objects.requireNonNull(c3050m);
                        int i4 = c3050m2.producerIndex;
                        AtomicReferenceArray<AbstractRunnableC3045h> atomicReferenceArray = c3050m2.f8391e;
                        for (int i5 = c3050m2.consumerIndex; i5 != i4; i5++) {
                            int i6 = i5 & 127;
                            if (c3050m2.blockingTasksInBuffer == 0) {
                                break;
                            }
                            AbstractRunnableC3045h abstractRunnableC3045h = atomicReferenceArray.get(i6);
                            if (abstractRunnableC3045h != null) {
                                if ((abstractRunnableC3045h.f8380e.mo3540v() == 1) && atomicReferenceArray.compareAndSet(i6, abstractRunnableC3045h, null)) {
                                    C3050m.f8390d.decrementAndGet(c3050m2);
                                    c3050m.m3542a(abstractRunnableC3045h, false);
                                    m3548g = -1;
                                    break;
                                }
                            }
                        }
                        m3548g = c3050m.m3548g(c3050m2, true);
                    } else {
                        C3050m c3050m3 = this.f8357e;
                        C3050m c3050m4 = aVar.f8357e;
                        Objects.requireNonNull(c3050m3);
                        AbstractRunnableC3045h m3547f = c3050m4.m3547f();
                        if (m3547f != null) {
                            c3050m3.m3542a(m3547f, false);
                            m3548g = -1;
                        } else {
                            m3548g = c3050m3.m3548g(c3050m4, false);
                        }
                    }
                    if (m3548g == -1) {
                        return this.f8357e.m3546e();
                    }
                    if (m3548g > 0) {
                        j2 = Math.min(j2, m3548g);
                    }
                }
            }
            if (j2 == Long.MAX_VALUE) {
                j2 = 0;
            }
            this.f8360h = j2;
            return null;
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            long j2;
            int i2;
            loop0: while (true) {
                boolean z = false;
                while (ExecutorC3038a.this._isTerminated == 0 && this.f8358f != 5) {
                    AbstractRunnableC3045h m3532a = m3532a(this.f8362j);
                    if (m3532a != null) {
                        this.f8360h = 0L;
                        int mo3540v = m3532a.f8380e.mo3540v();
                        this.f8359g = 0L;
                        if (this.f8358f == 3) {
                            this.f8358f = 2;
                        }
                        if (mo3540v != 0 && m3536e(2)) {
                            ExecutorC3038a.this.m3531v();
                        }
                        ExecutorC3038a.this.m3530t(m3532a);
                        if (mo3540v != 0) {
                            ExecutorC3038a.f8346e.addAndGet(ExecutorC3038a.this, -2097152L);
                            if (this.f8358f != 5) {
                                this.f8358f = 4;
                            }
                        }
                    } else {
                        this.f8362j = false;
                        if (this.f8360h == 0) {
                            Object obj = this.nextParkedWorker;
                            C2970s c2970s = ExecutorC3038a.f8348g;
                            if (obj != c2970s) {
                                this.workerCtl = -1;
                                while (true) {
                                    if ((this.nextParkedWorker != ExecutorC3038a.f8348g) && ExecutorC3038a.this._isTerminated == 0 && this.f8358f != 5) {
                                        m3536e(3);
                                        Thread.interrupted();
                                        if (this.f8359g == 0) {
                                            this.f8359g = System.nanoTime() + ExecutorC3038a.this.f8354m;
                                        }
                                        LockSupport.parkNanos(ExecutorC3038a.this.f8354m);
                                        if (System.nanoTime() - this.f8359g >= 0) {
                                            this.f8359g = 0L;
                                            synchronized (ExecutorC3038a.this.f8351j) {
                                                if (ExecutorC3038a.this._isTerminated == 0) {
                                                    if (((int) (ExecutorC3038a.this.controlState & 2097151)) > ExecutorC3038a.this.f8352k) {
                                                        if (f8356c.compareAndSet(this, -1, 1)) {
                                                            int i3 = this.indexInArray;
                                                            m3535d(0);
                                                            ExecutorC3038a.this.m3529s(this, i3, 0);
                                                            int andDecrement = (int) (ExecutorC3038a.f8346e.getAndDecrement(ExecutorC3038a.this) & 2097151);
                                                            if (andDecrement != i3) {
                                                                a aVar = ExecutorC3038a.this.f8351j.get(andDecrement);
                                                                Intrinsics.checkNotNull(aVar);
                                                                a aVar2 = aVar;
                                                                ExecutorC3038a.this.f8351j.set(i3, aVar2);
                                                                aVar2.m3535d(i3);
                                                                ExecutorC3038a.this.m3529s(aVar2, andDecrement, i3);
                                                            }
                                                            ExecutorC3038a.this.f8351j.set(andDecrement, null);
                                                            Unit unit = Unit.INSTANCE;
                                                            this.f8358f = 5;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                ExecutorC3038a executorC3038a = ExecutorC3038a.this;
                                Objects.requireNonNull(executorC3038a);
                                if (this.nextParkedWorker == c2970s) {
                                    do {
                                        j2 = executorC3038a.parkedWorkersStack;
                                        i2 = this.indexInArray;
                                        this.nextParkedWorker = executorC3038a.f8351j.get((int) (j2 & 2097151));
                                    } while (!ExecutorC3038a.f8345c.compareAndSet(executorC3038a, j2, i2 | ((2097152 + j2) & (-2097152))));
                                }
                            }
                        } else if (z) {
                            m3536e(3);
                            Thread.interrupted();
                            LockSupport.parkNanos(this.f8360h);
                            this.f8360h = 0L;
                        } else {
                            z = true;
                        }
                    }
                }
            }
            m3536e(5);
        }
    }

    public ExecutorC3038a(int i2, int i3, long j2, @NotNull String str) {
        this.f8352k = i2;
        this.f8353l = i3;
        this.f8354m = j2;
        this.f8355n = str;
        if (!(i2 >= 1)) {
            throw new IllegalArgumentException(C1499a.m628n("Core pool size ", i2, " should be at least 1").toString());
        }
        if (!(i3 >= i2)) {
            throw new IllegalArgumentException(C1499a.m629o("Max pool size ", i3, " should be greater than or equals to core pool size ", i2).toString());
        }
        if (!(i3 <= 2097150)) {
            throw new IllegalArgumentException(C1499a.m628n("Max pool size ", i3, " should not exceed maximal supported number of threads 2097150").toString());
        }
        if (!(j2 > 0)) {
            throw new IllegalArgumentException(C1499a.m631q("Idle worker keep alive time ", j2, " must be positive").toString());
        }
        this.f8349h = new C3041d();
        this.f8350i = new C3041d();
        this.parkedWorkersStack = 0L;
        this.f8351j = new AtomicReferenceArray<>(i3 + 1);
        this.controlState = i2 << 42;
        this._isTerminated = 0;
    }

    /* renamed from: o */
    public static /* synthetic */ void m3521o(ExecutorC3038a executorC3038a, Runnable runnable, InterfaceC3046i interfaceC3046i, boolean z, int i2) {
        C3044g c3044g = (i2 & 2) != 0 ? C3044g.f8378c : null;
        if ((i2 & 4) != 0) {
            z = false;
        }
        executorC3038a.m3527k(runnable, c3044g, z);
    }

    /* renamed from: C */
    public final boolean m3522C(long j2) {
        if (RangesKt___RangesKt.coerceAtLeast(((int) (2097151 & j2)) - ((int) ((j2 & 4398044413952L) >> 21)), 0) < this.f8352k) {
            int m3524b = m3524b();
            if (m3524b == 1 && this.f8352k > 1) {
                m3524b();
            }
            if (m3524b > 0) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: D */
    public final boolean m3523D() {
        while (true) {
            long j2 = this.parkedWorkersStack;
            a aVar = this.f8351j.get((int) (2097151 & j2));
            if (aVar != null) {
                long j3 = (2097152 + j2) & (-2097152);
                int m3528q = m3528q(aVar);
                if (m3528q >= 0 && f8345c.compareAndSet(this, j2, m3528q | j3)) {
                    aVar.nextParkedWorker = f8348g;
                }
            } else {
                aVar = null;
            }
            if (aVar == null) {
                return false;
            }
            if (a.f8356c.compareAndSet(aVar, -1, 0)) {
                LockSupport.unpark(aVar);
                return true;
            }
        }
    }

    /* renamed from: b */
    public final int m3524b() {
        synchronized (this.f8351j) {
            if (this._isTerminated != 0) {
                return -1;
            }
            long j2 = this.controlState;
            int i2 = (int) (j2 & 2097151);
            int coerceAtLeast = RangesKt___RangesKt.coerceAtLeast(i2 - ((int) ((j2 & 4398044413952L) >> 21)), 0);
            if (coerceAtLeast >= this.f8352k) {
                return 0;
            }
            if (i2 >= this.f8353l) {
                return 0;
            }
            int i3 = ((int) (this.controlState & 2097151)) + 1;
            if (!(i3 > 0 && this.f8351j.get(i3) == null)) {
                throw new IllegalArgumentException("Failed requirement.".toString());
            }
            a aVar = new a(i3);
            this.f8351j.set(i3, aVar);
            if (!(i3 == ((int) (2097151 & f8346e.incrementAndGet(this))))) {
                throw new IllegalArgumentException("Failed requirement.".toString());
            }
            aVar.start();
            return coerceAtLeast + 1;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0073, code lost:
    
        if (r1 != null) goto L34;
     */
    @Override // java.io.Closeable, java.lang.AutoCloseable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void close() {
        /*
            r9 = this;
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r0 = p379c.p380a.p385c2.ExecutorC3038a.f8347f
            r1 = 0
            r2 = 1
            boolean r0 = r0.compareAndSet(r9, r1, r2)
            if (r0 != 0) goto Lc
            goto L9b
        Lc:
            c.a.c2.a$a r0 = r9.m3526e()
            java.util.concurrent.atomic.AtomicReferenceArray<c.a.c2.a$a> r3 = r9.f8351j
            monitor-enter(r3)
            long r4 = r9.controlState     // Catch: java.lang.Throwable -> L9c
            r6 = 2097151(0x1fffff, double:1.0361303E-317)
            long r4 = r4 & r6
            int r5 = (int) r4
            monitor-exit(r3)
            if (r2 > r5) goto L63
            r3 = 1
        L1e:
            java.util.concurrent.atomic.AtomicReferenceArray<c.a.c2.a$a> r4 = r9.f8351j
            java.lang.Object r4 = r4.get(r3)
            kotlin.jvm.internal.Intrinsics.checkNotNull(r4)
            c.a.c2.a$a r4 = (p379c.p380a.p385c2.ExecutorC3038a.a) r4
            if (r4 == r0) goto L5e
        L2b:
            boolean r6 = r4.isAlive()
            if (r6 == 0) goto L3a
            java.util.concurrent.locks.LockSupport.unpark(r4)
            r6 = 10000(0x2710, double:4.9407E-320)
            r4.join(r6)
            goto L2b
        L3a:
            c.a.c2.m r4 = r4.f8357e
            c.a.c2.d r6 = r9.f8350i
            java.util.Objects.requireNonNull(r4)
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r7 = p379c.p380a.p385c2.C3050m.f8387a
            r8 = 0
            java.lang.Object r7 = r7.getAndSet(r4, r8)
            c.a.c2.h r7 = (p379c.p380a.p385c2.AbstractRunnableC3045h) r7
            if (r7 == 0) goto L4f
            r6.m3434a(r7)
        L4f:
            c.a.c2.h r7 = r4.m3547f()
            if (r7 == 0) goto L5a
            r6.m3434a(r7)
            r7 = 1
            goto L5b
        L5a:
            r7 = 0
        L5b:
            if (r7 == 0) goto L5e
            goto L4f
        L5e:
            if (r3 == r5) goto L63
            int r3 = r3 + 1
            goto L1e
        L63:
            c.a.c2.d r1 = r9.f8350i
            r1.m3435b()
            c.a.c2.d r1 = r9.f8349h
            r1.m3435b()
        L6d:
            if (r0 == 0) goto L76
            c.a.c2.h r1 = r0.m3532a(r2)
            if (r1 == 0) goto L76
            goto L7e
        L76:
            c.a.c2.d r1 = r9.f8349h
            java.lang.Object r1 = r1.m3437d()
            c.a.c2.h r1 = (p379c.p380a.p385c2.AbstractRunnableC3045h) r1
        L7e:
            if (r1 == 0) goto L81
            goto L89
        L81:
            c.a.c2.d r1 = r9.f8350i
            java.lang.Object r1 = r1.m3437d()
            c.a.c2.h r1 = (p379c.p380a.p385c2.AbstractRunnableC3045h) r1
        L89:
            if (r1 == 0) goto L8f
            r9.m3530t(r1)
            goto L6d
        L8f:
            if (r0 == 0) goto L95
            r1 = 5
            r0.m3536e(r1)
        L95:
            r0 = 0
            r9.parkedWorkersStack = r0
            r9.controlState = r0
        L9b:
            return
        L9c:
            r0 = move-exception
            monitor-exit(r3)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p385c2.ExecutorC3038a.close():void");
    }

    @NotNull
    /* renamed from: d */
    public final AbstractRunnableC3045h m3525d(@NotNull Runnable runnable, @NotNull InterfaceC3046i interfaceC3046i) {
        long mo3541a = C3048k.f8386e.mo3541a();
        if (!(runnable instanceof AbstractRunnableC3045h)) {
            return new C3047j(runnable, mo3541a, interfaceC3046i);
        }
        AbstractRunnableC3045h abstractRunnableC3045h = (AbstractRunnableC3045h) runnable;
        abstractRunnableC3045h.f8379c = mo3541a;
        abstractRunnableC3045h.f8380e = interfaceC3046i;
        return abstractRunnableC3045h;
    }

    /* renamed from: e */
    public final a m3526e() {
        Thread currentThread = Thread.currentThread();
        if (!(currentThread instanceof a)) {
            currentThread = null;
        }
        a aVar = (a) currentThread;
        if (aVar == null || !Intrinsics.areEqual(ExecutorC3038a.this, this)) {
            return null;
        }
        return aVar;
    }

    @Override // java.util.concurrent.Executor
    public void execute(@NotNull Runnable runnable) {
        m3521o(this, runnable, null, false, 6);
    }

    /* renamed from: k */
    public final void m3527k(@NotNull Runnable runnable, @NotNull InterfaceC3046i interfaceC3046i, boolean z) {
        AbstractRunnableC3045h abstractRunnableC3045h;
        AbstractRunnableC3045h m3525d = m3525d(runnable, interfaceC3046i);
        a m3526e = m3526e();
        if (m3526e == null || m3526e.f8358f == 5 || (m3525d.f8380e.mo3540v() == 0 && m3526e.f8358f == 2)) {
            abstractRunnableC3045h = m3525d;
        } else {
            m3526e.f8362j = true;
            abstractRunnableC3045h = m3526e.f8357e.m3542a(m3525d, z);
        }
        if (abstractRunnableC3045h != null) {
            if (!(abstractRunnableC3045h.f8380e.mo3540v() == 1 ? this.f8350i.m3434a(abstractRunnableC3045h) : this.f8349h.m3434a(abstractRunnableC3045h))) {
                throw new RejectedExecutionException(C1499a.m582D(new StringBuilder(), this.f8355n, " was terminated"));
            }
        }
        boolean z2 = z && m3526e != null;
        if (m3525d.f8380e.mo3540v() == 0) {
            if (z2) {
                return;
            }
            m3531v();
        } else {
            long addAndGet = f8346e.addAndGet(this, 2097152L);
            if (z2 || m3523D() || m3522C(addAndGet)) {
                return;
            }
            m3523D();
        }
    }

    /* renamed from: q */
    public final int m3528q(a aVar) {
        Object obj = aVar.nextParkedWorker;
        while (obj != f8348g) {
            if (obj == null) {
                return 0;
            }
            a aVar2 = (a) obj;
            int i2 = aVar2.indexInArray;
            if (i2 != 0) {
                return i2;
            }
            obj = aVar2.nextParkedWorker;
        }
        return -1;
    }

    /* renamed from: s */
    public final void m3529s(@NotNull a aVar, int i2, int i3) {
        while (true) {
            long j2 = this.parkedWorkersStack;
            int i4 = (int) (2097151 & j2);
            long j3 = (2097152 + j2) & (-2097152);
            if (i4 == i2) {
                i4 = i3 == 0 ? m3528q(aVar) : i3;
            }
            if (i4 >= 0 && f8345c.compareAndSet(this, j2, j3 | i4)) {
                return;
            }
        }
    }

    /* renamed from: t */
    public final void m3530t(@NotNull AbstractRunnableC3045h abstractRunnableC3045h) {
        try {
            abstractRunnableC3045h.run();
        } finally {
        }
    }

    @NotNull
    public String toString() {
        ArrayList arrayList = new ArrayList();
        int length = this.f8351j.length();
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        for (int i7 = 1; i7 < length; i7++) {
            a aVar = this.f8351j.get(i7);
            if (aVar != null) {
                int m3545d = aVar.f8357e.m3545d();
                int m350b = C1345b.m350b(aVar.f8358f);
                if (m350b == 0) {
                    i2++;
                    arrayList.add(String.valueOf(m3545d) + "c");
                } else if (m350b == 1) {
                    i3++;
                    arrayList.add(String.valueOf(m3545d) + "b");
                } else if (m350b == 2) {
                    i4++;
                } else if (m350b == 3) {
                    i5++;
                    if (m3545d > 0) {
                        arrayList.add(String.valueOf(m3545d) + "d");
                    }
                } else if (m350b == 4) {
                    i6++;
                }
            }
        }
        long j2 = this.controlState;
        return this.f8355n + '@' + C2354n.m2495m0(this) + "[Pool Size {core = " + this.f8352k + ", max = " + this.f8353l + "}, Worker States {CPU = " + i2 + ", blocking = " + i3 + ", parked = " + i4 + ", dormant = " + i5 + ", terminated = " + i6 + "}, running workers queues = " + arrayList + ", global CPU queue size = " + this.f8349h.m3436c() + ", global blocking queue size = " + this.f8350i.m3436c() + ", Control State {created workers= " + ((int) (2097151 & j2)) + ", blocking tasks = " + ((int) ((4398044413952L & j2) >> 21)) + ", CPUs acquired = " + (this.f8352k - ((int) ((9223367638808264704L & j2) >> 42))) + "}]";
    }

    /* renamed from: v */
    public final void m3531v() {
        if (m3523D() || m3522C(this.controlState)) {
            return;
        }
        m3523D();
    }
}
