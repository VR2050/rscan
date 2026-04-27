package Q2;

import java.io.InterruptedIOException;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class G {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f2524a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private long f2525b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f2526c;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final b f2523e = new b(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final G f2522d = new a();

    public static final class b {
        private b() {
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public G a() {
        this.f2524a = false;
        return this;
    }

    public G b() {
        this.f2526c = 0L;
        return this;
    }

    public long c() {
        if (this.f2524a) {
            return this.f2525b;
        }
        throw new IllegalStateException("No deadline");
    }

    public G d(long j3) {
        this.f2524a = true;
        this.f2525b = j3;
        return this;
    }

    public boolean e() {
        return this.f2524a;
    }

    public void f() throws InterruptedIOException {
        if (Thread.interrupted()) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
        }
        if (this.f2524a && this.f2525b - System.nanoTime() <= 0) {
            throw new InterruptedIOException("deadline reached");
        }
    }

    public G g(long j3, TimeUnit timeUnit) {
        t2.j.f(timeUnit, "unit");
        if (j3 >= 0) {
            this.f2526c = timeUnit.toNanos(j3);
            return this;
        }
        throw new IllegalArgumentException(("timeout < 0: " + j3).toString());
    }

    public long h() {
        return this.f2526c;
    }

    public static final class a extends G {
        a() {
        }

        @Override // Q2.G
        public G g(long j3, TimeUnit timeUnit) {
            t2.j.f(timeUnit, "unit");
            return this;
        }

        @Override // Q2.G
        public void f() {
        }

        @Override // Q2.G
        public G d(long j3) {
            return this;
        }
    }
}
