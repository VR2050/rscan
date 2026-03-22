package p379c.p380a.p385c2;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.c2.m */
/* loaded from: classes2.dex */
public final class C3050m {

    /* renamed from: a */
    public static final AtomicReferenceFieldUpdater f8387a = AtomicReferenceFieldUpdater.newUpdater(C3050m.class, Object.class, "lastScheduledTask");

    /* renamed from: b */
    public static final AtomicIntegerFieldUpdater f8388b = AtomicIntegerFieldUpdater.newUpdater(C3050m.class, "producerIndex");

    /* renamed from: c */
    public static final AtomicIntegerFieldUpdater f8389c = AtomicIntegerFieldUpdater.newUpdater(C3050m.class, "consumerIndex");

    /* renamed from: d */
    public static final AtomicIntegerFieldUpdater f8390d = AtomicIntegerFieldUpdater.newUpdater(C3050m.class, "blockingTasksInBuffer");

    /* renamed from: e */
    public final AtomicReferenceArray<AbstractRunnableC3045h> f8391e = new AtomicReferenceArray<>(128);
    public volatile Object lastScheduledTask = null;
    public volatile int producerIndex = 0;
    public volatile int consumerIndex = 0;
    public volatile int blockingTasksInBuffer = 0;

    @Nullable
    /* renamed from: a */
    public final AbstractRunnableC3045h m3542a(@NotNull AbstractRunnableC3045h abstractRunnableC3045h, boolean z) {
        if (z) {
            return m3543b(abstractRunnableC3045h);
        }
        AbstractRunnableC3045h abstractRunnableC3045h2 = (AbstractRunnableC3045h) f8387a.getAndSet(this, abstractRunnableC3045h);
        if (abstractRunnableC3045h2 != null) {
            return m3543b(abstractRunnableC3045h2);
        }
        return null;
    }

    /* renamed from: b */
    public final AbstractRunnableC3045h m3543b(AbstractRunnableC3045h abstractRunnableC3045h) {
        if (abstractRunnableC3045h.f8380e.mo3540v() == 1) {
            f8390d.incrementAndGet(this);
        }
        if (m3544c() == 127) {
            return abstractRunnableC3045h;
        }
        int i2 = this.producerIndex & 127;
        while (this.f8391e.get(i2) != null) {
            Thread.yield();
        }
        this.f8391e.lazySet(i2, abstractRunnableC3045h);
        f8388b.incrementAndGet(this);
        return null;
    }

    /* renamed from: c */
    public final int m3544c() {
        return this.producerIndex - this.consumerIndex;
    }

    /* renamed from: d */
    public final int m3545d() {
        return this.lastScheduledTask != null ? m3544c() + 1 : m3544c();
    }

    @Nullable
    /* renamed from: e */
    public final AbstractRunnableC3045h m3546e() {
        AbstractRunnableC3045h abstractRunnableC3045h = (AbstractRunnableC3045h) f8387a.getAndSet(this, null);
        return abstractRunnableC3045h != null ? abstractRunnableC3045h : m3547f();
    }

    /* renamed from: f */
    public final AbstractRunnableC3045h m3547f() {
        AbstractRunnableC3045h andSet;
        while (true) {
            int i2 = this.consumerIndex;
            if (i2 - this.producerIndex == 0) {
                return null;
            }
            int i3 = i2 & 127;
            if (f8389c.compareAndSet(this, i2, i2 + 1) && (andSet = this.f8391e.getAndSet(i3, null)) != null) {
                if (andSet.f8380e.mo3540v() == 1) {
                    f8390d.decrementAndGet(this);
                }
                return andSet;
            }
        }
    }

    /* renamed from: g */
    public final long m3548g(C3050m c3050m, boolean z) {
        AbstractRunnableC3045h abstractRunnableC3045h;
        do {
            abstractRunnableC3045h = (AbstractRunnableC3045h) c3050m.lastScheduledTask;
            if (abstractRunnableC3045h == null) {
                return -2L;
            }
            if (z) {
                if (!(abstractRunnableC3045h.f8380e.mo3540v() == 1)) {
                    return -2L;
                }
            }
            long mo3541a = C3048k.f8386e.mo3541a() - abstractRunnableC3045h.f8379c;
            long j2 = C3048k.f8382a;
            if (mo3541a < j2) {
                return j2 - mo3541a;
            }
        } while (!f8387a.compareAndSet(c3050m, abstractRunnableC3045h, null));
        m3542a(abstractRunnableC3045h, false);
        return -1L;
    }
}
