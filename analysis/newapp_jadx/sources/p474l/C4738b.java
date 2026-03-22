package p474l;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: l.b */
/* loaded from: classes3.dex */
public class C4738b extends C4737a0 {

    /* renamed from: e */
    public static final long f12119e;

    /* renamed from: f */
    public static final long f12120f;

    /* renamed from: g */
    public static C4738b f12121g;

    /* renamed from: h */
    public static final a f12122h = new a(null);

    /* renamed from: i */
    public boolean f12123i;

    /* renamed from: j */
    public C4738b f12124j;

    /* renamed from: k */
    public long f12125k;

    /* renamed from: l.b$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        @Nullable
        /* renamed from: a */
        public final C4738b m5346a() {
            C4738b c4738b = C4738b.f12121g;
            Intrinsics.checkNotNull(c4738b);
            C4738b c4738b2 = c4738b.f12124j;
            if (c4738b2 == null) {
                long nanoTime = System.nanoTime();
                C4738b.class.wait(C4738b.f12119e);
                C4738b c4738b3 = C4738b.f12121g;
                Intrinsics.checkNotNull(c4738b3);
                if (c4738b3.f12124j != null || System.nanoTime() - nanoTime < C4738b.f12120f) {
                    return null;
                }
                return C4738b.f12121g;
            }
            long nanoTime2 = c4738b2.f12125k - System.nanoTime();
            if (nanoTime2 > 0) {
                long j2 = nanoTime2 / 1000000;
                C4738b.class.wait(j2, (int) (nanoTime2 - (1000000 * j2)));
                return null;
            }
            C4738b c4738b4 = C4738b.f12121g;
            Intrinsics.checkNotNull(c4738b4);
            c4738b4.f12124j = c4738b2.f12124j;
            c4738b2.f12124j = null;
            return c4738b2;
        }
    }

    /* renamed from: l.b$b */
    public static final class b extends Thread {
        public b() {
            super("Okio Watchdog");
            setDaemon(true);
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            C4738b m5346a;
            while (true) {
                try {
                    synchronized (C4738b.class) {
                        m5346a = C4738b.f12122h.m5346a();
                        if (m5346a == C4738b.f12121g) {
                            C4738b.f12121g = null;
                            return;
                        }
                        Unit unit = Unit.INSTANCE;
                    }
                    if (m5346a != null) {
                        m5346a.mo5125k();
                    }
                } catch (InterruptedException unused) {
                }
            }
        }
    }

    static {
        long millis = TimeUnit.SECONDS.toMillis(60L);
        f12119e = millis;
        f12120f = TimeUnit.MILLISECONDS.toNanos(millis);
    }

    /* renamed from: h */
    public final void m5344h() {
        if (!(!this.f12123i)) {
            throw new IllegalStateException("Unbalanced enter/exit".toString());
        }
        long j2 = this.f12118d;
        boolean z = this.f12116b;
        if (j2 != 0 || z) {
            this.f12123i = true;
            synchronized (C4738b.class) {
                if (f12121g == null) {
                    f12121g = new C4738b();
                    new b().start();
                }
                long nanoTime = System.nanoTime();
                if (j2 != 0 && z) {
                    this.f12125k = Math.min(j2, mo5339c() - nanoTime) + nanoTime;
                } else if (j2 != 0) {
                    this.f12125k = j2 + nanoTime;
                } else {
                    if (!z) {
                        throw new AssertionError();
                    }
                    this.f12125k = mo5339c();
                }
                long j3 = this.f12125k - nanoTime;
                C4738b c4738b = f12121g;
                Intrinsics.checkNotNull(c4738b);
                while (true) {
                    C4738b c4738b2 = c4738b.f12124j;
                    if (c4738b2 == null) {
                        break;
                    }
                    Intrinsics.checkNotNull(c4738b2);
                    if (j3 < c4738b2.f12125k - nanoTime) {
                        break;
                    }
                    c4738b = c4738b.f12124j;
                    Intrinsics.checkNotNull(c4738b);
                }
                this.f12124j = c4738b.f12124j;
                c4738b.f12124j = this;
                if (c4738b == f12121g) {
                    C4738b.class.notify();
                }
                Unit unit = Unit.INSTANCE;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0013, code lost:
    
        r2.f12124j = r4.f12124j;
        r4.f12124j = null;
     */
    /* renamed from: i */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m5345i() {
        /*
            r4 = this;
            boolean r0 = r4.f12123i
            r1 = 0
            if (r0 != 0) goto L6
            return r1
        L6:
            r4.f12123i = r1
            java.lang.Class<l.b> r0 = p474l.C4738b.class
            monitor-enter(r0)
            l.b r2 = p474l.C4738b.f12121g     // Catch: java.lang.Throwable -> L21
        Ld:
            if (r2 == 0) goto L1e
            l.b r3 = r2.f12124j     // Catch: java.lang.Throwable -> L21
            if (r3 != r4) goto L1c
            l.b r3 = r4.f12124j     // Catch: java.lang.Throwable -> L21
            r2.f12124j = r3     // Catch: java.lang.Throwable -> L21
            r2 = 0
            r4.f12124j = r2     // Catch: java.lang.Throwable -> L21
            monitor-exit(r0)
            goto L20
        L1c:
            r2 = r3
            goto Ld
        L1e:
            r1 = 1
            monitor-exit(r0)
        L20:
            return r1
        L21:
            r1 = move-exception
            monitor-exit(r0)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.C4738b.m5345i():boolean");
    }

    @NotNull
    /* renamed from: j */
    public IOException mo5205j(@Nullable IOException iOException) {
        InterruptedIOException interruptedIOException = new InterruptedIOException("timeout");
        if (iOException != null) {
            interruptedIOException.initCause(iOException);
        }
        return interruptedIOException;
    }

    /* renamed from: k */
    public void mo5125k() {
    }
}
