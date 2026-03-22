package p379c.p380a;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import kotlin.ranges.RangesKt___RangesKt;
import org.jetbrains.annotations.NotNull;

/* renamed from: c.a.g0 */
/* loaded from: classes2.dex */
public final class RunnableC3061g0 extends AbstractC3094r0 implements Runnable {
    public static volatile Thread _thread;
    public static volatile int debugStatus;

    /* renamed from: j */
    public static final long f8399j;

    /* renamed from: k */
    public static final RunnableC3061g0 f8400k;

    static {
        Long l2;
        RunnableC3061g0 runnableC3061g0 = new RunnableC3061g0();
        f8400k = runnableC3061g0;
        runnableC3061g0.m3629X(false);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        try {
            l2 = Long.getLong("kotlinx.coroutines.DefaultExecutor.keepAlive", 1000L);
        } catch (SecurityException unused) {
            l2 = 1000L;
        }
        f8399j = timeUnit.toNanos(l2.longValue());
    }

    @Override // p379c.p380a.AbstractC3097s0
    @NotNull
    /* renamed from: b0 */
    public Thread mo3554b0() {
        Thread thread = _thread;
        if (thread == null) {
            synchronized (this) {
                thread = _thread;
                if (thread == null) {
                    thread = new Thread(this, "kotlinx.coroutines.DefaultExecutor");
                    _thread = thread;
                    thread.setDaemon(true);
                    thread.start();
                }
            }
        }
        return thread;
    }

    /* renamed from: g0 */
    public final synchronized void m3555g0() {
        if (m3556h0()) {
            debugStatus = 3;
            this._queue = null;
            this._delayed = null;
            notifyAll();
        }
    }

    /* renamed from: h0 */
    public final boolean m3556h0() {
        int i2 = debugStatus;
        return i2 == 2 || i2 == 3;
    }

    @Override // java.lang.Runnable
    public void run() {
        boolean z;
        boolean m3635e0;
        C3107v1 c3107v1 = C3107v1.f8468b;
        C3107v1.f8467a.set(this);
        try {
            synchronized (this) {
                if (m3556h0()) {
                    z = false;
                } else {
                    z = true;
                    debugStatus = 1;
                    notifyAll();
                }
            }
            if (!z) {
                if (m3635e0) {
                    return;
                } else {
                    return;
                }
            }
            long j2 = Long.MAX_VALUE;
            while (true) {
                Thread.interrupted();
                long mo3631Z = mo3631Z();
                if (mo3631Z == Long.MAX_VALUE) {
                    long nanoTime = System.nanoTime();
                    if (j2 == Long.MAX_VALUE) {
                        j2 = f8399j + nanoTime;
                    }
                    long j3 = j2 - nanoTime;
                    if (j3 <= 0) {
                        _thread = null;
                        m3555g0();
                        if (m3635e0()) {
                            return;
                        }
                        mo3554b0();
                        return;
                    }
                    mo3631Z = RangesKt___RangesKt.coerceAtMost(mo3631Z, j3);
                } else {
                    j2 = Long.MAX_VALUE;
                }
                if (mo3631Z > 0) {
                    if (m3556h0()) {
                        _thread = null;
                        m3555g0();
                        if (m3635e0()) {
                            return;
                        }
                        mo3554b0();
                        return;
                    }
                    LockSupport.parkNanos(this, mo3631Z);
                }
            }
        } finally {
            _thread = null;
            m3555g0();
            if (!m3635e0()) {
                mo3554b0();
            }
        }
    }
}
