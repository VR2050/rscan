package p379c.p380a.p381a;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.a.k */
/* loaded from: classes2.dex */
public class C2962k<E> {

    /* renamed from: a */
    public static final AtomicReferenceFieldUpdater f8116a = AtomicReferenceFieldUpdater.newUpdater(C2962k.class, Object.class, "_cur");
    public volatile Object _cur;

    public C2962k(boolean z) {
        this._cur = new C2963l(8, z);
    }

    /* renamed from: a */
    public final boolean m3434a(@NotNull E e2) {
        while (true) {
            C2963l c2963l = (C2963l) this._cur;
            int m3438a = c2963l.m3438a(e2);
            if (m3438a == 0) {
                return true;
            }
            if (m3438a == 1) {
                f8116a.compareAndSet(this, c2963l, c2963l.m3441d());
            } else if (m3438a == 2) {
                return false;
            }
        }
    }

    /* renamed from: b */
    public final void m3435b() {
        while (true) {
            C2963l c2963l = (C2963l) this._cur;
            if (c2963l.m3439b()) {
                return;
            } else {
                f8116a.compareAndSet(this, c2963l, c2963l.m3441d());
            }
        }
    }

    /* renamed from: c */
    public final int m3436c() {
        long j2 = ((C2963l) this._cur)._state;
        return 1073741823 & (((int) ((j2 & 1152921503533105152L) >> 30)) - ((int) ((1073741823 & j2) >> 0)));
    }

    @Nullable
    /* renamed from: d */
    public final E m3437d() {
        while (true) {
            C2963l c2963l = (C2963l) this._cur;
            E e2 = (E) c2963l.m3442e();
            if (e2 != C2963l.f8119c) {
                return e2;
            }
            f8116a.compareAndSet(this, c2963l, c2963l.m3441d());
        }
    }
}
