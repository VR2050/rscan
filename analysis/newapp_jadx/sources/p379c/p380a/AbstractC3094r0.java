package p379c.p380a;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.concurrent.locks.LockSupport;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.JvmField;
import kotlin.time.DurationKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.p381a.C2953b;
import p379c.p380a.p381a.C2963l;
import p379c.p380a.p381a.C2970s;
import p379c.p380a.p381a.C2972u;
import p379c.p380a.p381a.InterfaceC2973v;

/* renamed from: c.a.r0 */
/* loaded from: classes2.dex */
public abstract class AbstractC3094r0 extends AbstractC3097s0 implements InterfaceC3070j0 {

    /* renamed from: h */
    public static final AtomicReferenceFieldUpdater f8446h = AtomicReferenceFieldUpdater.newUpdater(AbstractC3094r0.class, Object.class, "_queue");

    /* renamed from: i */
    public static final AtomicReferenceFieldUpdater f8447i = AtomicReferenceFieldUpdater.newUpdater(AbstractC3094r0.class, Object.class, "_delayed");
    public volatile Object _queue = null;
    public volatile Object _delayed = null;
    public volatile int _isCompleted = 0;

    /* renamed from: c.a.r0$a */
    public final class a extends b {

        /* renamed from: g */
        public final InterfaceC3066i<Unit> f8448g;

        /* JADX WARN: Multi-variable type inference failed */
        public a(long j2, @NotNull InterfaceC3066i<? super Unit> interfaceC3066i) {
            super(j2);
            this.f8448g = interfaceC3066i;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f8448g.mo3565i(AbstractC3094r0.this, Unit.INSTANCE);
        }

        @Override // p379c.p380a.AbstractC3094r0.b
        @NotNull
        public String toString() {
            return super.toString() + this.f8448g.toString();
        }
    }

    /* renamed from: c.a.r0$b */
    public static abstract class b implements Runnable, Comparable<b>, InterfaceC3082n0, InterfaceC2973v {

        /* renamed from: c */
        public Object f8450c;

        /* renamed from: e */
        public int f8451e = -1;

        /* renamed from: f */
        @JvmField
        public long f8452f;

        public b(long j2) {
            this.f8452f = j2;
        }

        @Override // p379c.p380a.p381a.InterfaceC2973v
        /* renamed from: a */
        public void mo3452a(int i2) {
            this.f8451e = i2;
        }

        @Override // p379c.p380a.p381a.InterfaceC2973v
        /* renamed from: b */
        public void mo3453b(@Nullable C2972u<?> c2972u) {
            if (!(this.f8450c != C3100t0.f8459a)) {
                throw new IllegalArgumentException("Failed requirement.".toString());
            }
            this.f8450c = c2972u;
        }

        @Override // java.lang.Comparable
        public int compareTo(b bVar) {
            long j2 = this.f8452f - bVar.f8452f;
            if (j2 > 0) {
                return 1;
            }
            return j2 < 0 ? -1 : 0;
        }

        @Override // p379c.p380a.p381a.InterfaceC2973v
        @Nullable
        /* renamed from: d */
        public C2972u<?> mo3454d() {
            Object obj = this.f8450c;
            if (!(obj instanceof C2972u)) {
                obj = null;
            }
            return (C2972u) obj;
        }

        @Override // p379c.p380a.InterfaceC3082n0
        public final synchronized void dispose() {
            Object obj = this.f8450c;
            C2970s c2970s = C3100t0.f8459a;
            if (obj == c2970s) {
                return;
            }
            if (!(obj instanceof c)) {
                obj = null;
            }
            c cVar = (c) obj;
            if (cVar != null) {
                synchronized (cVar) {
                    if (mo3454d() != null) {
                        cVar.m3449c(getIndex());
                    }
                }
            }
            this.f8450c = c2970s;
        }

        @Override // p379c.p380a.p381a.InterfaceC2973v
        public int getIndex() {
            return this.f8451e;
        }

        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("Delayed[nanos=");
            m586H.append(this.f8452f);
            m586H.append(']');
            return m586H.toString();
        }
    }

    /* renamed from: c.a.r0$c */
    public static final class c extends C2972u<b> {

        /* renamed from: b */
        @JvmField
        public long f8453b;

        public c(long j2) {
            this.f8453b = j2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:61:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:86:? A[RETURN, SYNTHETIC] */
    @Override // p379c.p380a.AbstractC3091q0
    /* renamed from: Z */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long mo3631Z() {
        /*
            Method dump skipped, instructions count: 218
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.AbstractC3094r0.mo3631Z():long");
    }

    /* renamed from: c0 */
    public final void m3633c0(@NotNull Runnable runnable) {
        if (!m3634d0(runnable)) {
            RunnableC3061g0.f8400k.m3633c0(runnable);
            return;
        }
        Thread mo3554b0 = mo3554b0();
        if (Thread.currentThread() != mo3554b0) {
            LockSupport.unpark(mo3554b0);
        }
    }

    /* renamed from: d0 */
    public final boolean m3634d0(Runnable runnable) {
        while (true) {
            Object obj = this._queue;
            if (this._isCompleted != 0) {
                return false;
            }
            if (obj == null) {
                if (f8446h.compareAndSet(this, null, runnable)) {
                    return true;
                }
            } else if (obj instanceof C2963l) {
                C2963l c2963l = (C2963l) obj;
                int m3438a = c2963l.m3438a(runnable);
                if (m3438a == 0) {
                    return true;
                }
                if (m3438a == 1) {
                    f8446h.compareAndSet(this, obj, c2963l.m3441d());
                } else if (m3438a == 2) {
                    return false;
                }
            } else {
                if (obj == C3100t0.f8460b) {
                    return false;
                }
                C2963l c2963l2 = new C2963l(8, true);
                c2963l2.m3438a((Runnable) obj);
                c2963l2.m3438a(runnable);
                if (f8446h.compareAndSet(this, obj, c2963l2)) {
                    return true;
                }
            }
        }
    }

    @Override // p379c.p380a.AbstractC3036c0
    public final void dispatch(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        m3633c0(runnable);
    }

    @Override // p379c.p380a.InterfaceC3070j0
    /* renamed from: e */
    public void mo3617e(long j2, @NotNull InterfaceC3066i<? super Unit> interfaceC3066i) {
        long j3 = j2 > 0 ? j2 >= 9223372036854L ? Long.MAX_VALUE : 1000000 * j2 : 0L;
        if (j3 < DurationKt.MAX_MILLIS) {
            long nanoTime = System.nanoTime();
            a aVar = new a(j3 + nanoTime, interfaceC3066i);
            ((C3069j) interfaceC3066i).mo3562f(new C3085o0(aVar));
            m3636f0(nanoTime, aVar);
        }
    }

    /* renamed from: e0 */
    public boolean m3635e0() {
        C2953b<AbstractC3076l0<?>> c2953b = this.f8443g;
        if (!(c2953b == null || c2953b.f8097b == c2953b.f8098c)) {
            return false;
        }
        c cVar = (c) this._delayed;
        if (cVar != null) {
            if (!(cVar._size == 0)) {
                return false;
            }
        }
        Object obj = this._queue;
        if (obj == null) {
            return true;
        }
        return obj instanceof C2963l ? ((C2963l) obj).m3440c() : obj == C3100t0.f8460b;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x007e  */
    /* renamed from: f0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3636f0(long r13, @org.jetbrains.annotations.NotNull p379c.p380a.AbstractC3094r0.b r15) {
        /*
            r12 = this;
            int r0 = r12._isCompleted
            r1 = 2
            r2 = 0
            r3 = 1
            r4 = 0
            if (r0 == 0) goto L9
            goto L38
        L9:
            java.lang.Object r0 = r12._delayed
            c.a.r0$c r0 = (p379c.p380a.AbstractC3094r0.c) r0
            if (r0 == 0) goto L10
            goto L21
        L10:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r0 = p379c.p380a.AbstractC3094r0.f8447i
            c.a.r0$c r5 = new c.a.r0$c
            r5.<init>(r13)
            r0.compareAndSet(r12, r4, r5)
            java.lang.Object r0 = r12._delayed
            kotlin.jvm.internal.Intrinsics.checkNotNull(r0)
            c.a.r0$c r0 = (p379c.p380a.AbstractC3094r0.c) r0
        L21:
            monitor-enter(r15)
            java.lang.Object r5 = r15.f8450c     // Catch: java.lang.Throwable -> La7
            c.a.a.s r6 = p379c.p380a.C3100t0.f8459a     // Catch: java.lang.Throwable -> La7
            if (r5 != r6) goto L2b
            monitor-exit(r15)
            r0 = 2
            goto L65
        L2b:
            monitor-enter(r0)     // Catch: java.lang.Throwable -> La7
            c.a.a.v r5 = r0.m3448b()     // Catch: java.lang.Throwable -> La4
            c.a.r0$b r5 = (p379c.p380a.AbstractC3094r0.b) r5     // Catch: java.lang.Throwable -> La4
            int r6 = r12._isCompleted     // Catch: java.lang.Throwable -> La4
            if (r6 == 0) goto L3a
            monitor-exit(r0)     // Catch: java.lang.Throwable -> La7
            monitor-exit(r15)
        L38:
            r0 = 1
            goto L65
        L3a:
            r6 = 0
            if (r5 != 0) goto L41
            r0.f8453b = r13     // Catch: java.lang.Throwable -> La4
            goto L54
        L41:
            long r8 = r5.f8452f     // Catch: java.lang.Throwable -> La4
            long r10 = r8 - r13
            int r5 = (r10 > r6 ? 1 : (r10 == r6 ? 0 : -1))
            if (r5 < 0) goto L4a
            r8 = r13
        L4a:
            long r10 = r0.f8453b     // Catch: java.lang.Throwable -> La4
            long r10 = r8 - r10
            int r5 = (r10 > r6 ? 1 : (r10 == r6 ? 0 : -1))
            if (r5 <= 0) goto L54
            r0.f8453b = r8     // Catch: java.lang.Throwable -> La4
        L54:
            long r8 = r15.f8452f     // Catch: java.lang.Throwable -> La4
            long r10 = r0.f8453b     // Catch: java.lang.Throwable -> La4
            long r8 = r8 - r10
            int r5 = (r8 > r6 ? 1 : (r8 == r6 ? 0 : -1))
            if (r5 >= 0) goto L5f
            r15.f8452f = r10     // Catch: java.lang.Throwable -> La4
        L5f:
            r0.m3447a(r15)     // Catch: java.lang.Throwable -> La4
            monitor-exit(r0)     // Catch: java.lang.Throwable -> La7
            monitor-exit(r15)
            r0 = 0
        L65:
            if (r0 == 0) goto L7e
            if (r0 == r3) goto L78
            if (r0 != r1) goto L6c
            goto La3
        L6c:
            java.lang.String r13 = "unexpected result"
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r13 = r13.toString()
            r14.<init>(r13)
            throw r14
        L78:
            c.a.g0 r0 = p379c.p380a.RunnableC3061g0.f8400k
            r0.m3636f0(r13, r15)
            goto La3
        L7e:
            java.lang.Object r13 = r12._delayed
            c.a.r0$c r13 = (p379c.p380a.AbstractC3094r0.c) r13
            if (r13 == 0) goto L91
            monitor-enter(r13)
            c.a.a.v r14 = r13.m3448b()     // Catch: java.lang.Throwable -> L8e
            monitor-exit(r13)
            r4 = r14
            c.a.r0$b r4 = (p379c.p380a.AbstractC3094r0.b) r4
            goto L91
        L8e:
            r14 = move-exception
            monitor-exit(r13)
            throw r14
        L91:
            if (r4 != r15) goto L94
            r2 = 1
        L94:
            if (r2 == 0) goto La3
            java.lang.Thread r13 = r12.mo3554b0()
            java.lang.Thread r14 = java.lang.Thread.currentThread()
            if (r14 == r13) goto La3
            java.util.concurrent.locks.LockSupport.unpark(r13)
        La3:
            return
        La4:
            r13 = move-exception
            monitor-exit(r0)     // Catch: java.lang.Throwable -> La7
            throw r13     // Catch: java.lang.Throwable -> La7
        La7:
            r13 = move-exception
            monitor-exit(r15)
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.AbstractC3094r0.m3636f0(long, c.a.r0$b):void");
    }

    @Override // p379c.p380a.AbstractC3091q0
    public void shutdown() {
        b m3449c;
        C3107v1 c3107v1 = C3107v1.f8468b;
        C3107v1.f8467a.set(null);
        this._isCompleted = 1;
        while (true) {
            Object obj = this._queue;
            if (obj == null) {
                if (f8446h.compareAndSet(this, null, C3100t0.f8460b)) {
                    break;
                }
            } else if (obj instanceof C2963l) {
                ((C2963l) obj).m3439b();
                break;
            } else {
                if (obj == C3100t0.f8460b) {
                    break;
                }
                C2963l c2963l = new C2963l(8, true);
                c2963l.m3438a((Runnable) obj);
                if (f8446h.compareAndSet(this, obj, c2963l)) {
                    break;
                }
            }
        }
        while (mo3631Z() <= 0) {
        }
        long nanoTime = System.nanoTime();
        while (true) {
            c cVar = (c) this._delayed;
            if (cVar == null) {
                return;
            }
            synchronized (cVar) {
                m3449c = cVar._size > 0 ? cVar.m3449c(0) : null;
            }
            b bVar = m3449c;
            if (bVar == null) {
                return;
            } else {
                RunnableC3061g0.f8400k.m3636f0(nanoTime, bVar);
            }
        }
    }
}
