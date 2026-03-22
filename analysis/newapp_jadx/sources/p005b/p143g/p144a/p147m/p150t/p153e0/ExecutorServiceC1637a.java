package p005b.p143g.p144a.p147m.p150t.p153e0;

import android.os.Process;
import android.os.StrictMode;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/* renamed from: b.g.a.m.t.e0.a */
/* loaded from: classes.dex */
public final class ExecutorServiceC1637a implements ExecutorService {

    /* renamed from: c */
    public static final long f2137c = TimeUnit.SECONDS.toMillis(10);

    /* renamed from: e */
    public static volatile int f2138e;

    /* renamed from: f */
    public final ExecutorService f2139f;

    /* renamed from: b.g.a.m.t.e0.a$a */
    public static final class a implements ThreadFactory {

        /* renamed from: c */
        public final String f2140c;

        /* renamed from: e */
        public final boolean f2141e;

        /* renamed from: f */
        public int f2142f;

        /* renamed from: b.g.a.m.t.e0.a$a$a, reason: collision with other inner class name */
        public class C5107a extends Thread {
            public C5107a(Runnable runnable, String str) {
                super(runnable, str);
            }

            @Override // java.lang.Thread, java.lang.Runnable
            public void run() {
                Process.setThreadPriority(9);
                if (a.this.f2141e) {
                    StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder().detectNetwork().penaltyDeath().build());
                }
                try {
                    super.run();
                } catch (Throwable th) {
                    Objects.requireNonNull(a.this);
                    ((b.a) b.f2145b).m905a(th);
                }
            }
        }

        public a(String str, b bVar, boolean z) {
            this.f2140c = str;
            this.f2141e = z;
        }

        @Override // java.util.concurrent.ThreadFactory
        public synchronized Thread newThread(@NonNull Runnable runnable) {
            C5107a c5107a;
            c5107a = new C5107a(runnable, "glide-" + this.f2140c + "-thread-" + this.f2142f);
            this.f2142f = this.f2142f + 1;
            return c5107a;
        }
    }

    /* renamed from: b.g.a.m.t.e0.a$b */
    public interface b {

        /* renamed from: a */
        public static final b f2144a;

        /* renamed from: b */
        public static final b f2145b;

        /* renamed from: b.g.a.m.t.e0.a$b$a */
        public class a implements b {
            /* renamed from: a */
            public void m905a(Throwable th) {
                Log.isLoggable("GlideExecutor", 6);
            }
        }

        static {
            a aVar = new a();
            f2144a = aVar;
            f2145b = aVar;
        }
    }

    @VisibleForTesting
    public ExecutorServiceC1637a(ExecutorService executorService) {
        this.f2139f = executorService;
    }

    /* renamed from: a */
    public static int m904a() {
        if (f2138e == 0) {
            f2138e = Math.min(4, Runtime.getRuntime().availableProcessors());
        }
        return f2138e;
    }

    @Override // java.util.concurrent.ExecutorService
    public boolean awaitTermination(long j2, @NonNull TimeUnit timeUnit) {
        return this.f2139f.awaitTermination(j2, timeUnit);
    }

    @Override // java.util.concurrent.Executor
    public void execute(@NonNull Runnable runnable) {
        this.f2139f.execute(runnable);
    }

    @Override // java.util.concurrent.ExecutorService
    @NonNull
    public <T> List<Future<T>> invokeAll(@NonNull Collection<? extends Callable<T>> collection) {
        return this.f2139f.invokeAll(collection);
    }

    @Override // java.util.concurrent.ExecutorService
    @NonNull
    public <T> T invokeAny(@NonNull Collection<? extends Callable<T>> collection) {
        return (T) this.f2139f.invokeAny(collection);
    }

    @Override // java.util.concurrent.ExecutorService
    public boolean isShutdown() {
        return this.f2139f.isShutdown();
    }

    @Override // java.util.concurrent.ExecutorService
    public boolean isTerminated() {
        return this.f2139f.isTerminated();
    }

    @Override // java.util.concurrent.ExecutorService
    public void shutdown() {
        this.f2139f.shutdown();
    }

    @Override // java.util.concurrent.ExecutorService
    @NonNull
    public List<Runnable> shutdownNow() {
        return this.f2139f.shutdownNow();
    }

    @Override // java.util.concurrent.ExecutorService
    @NonNull
    public Future<?> submit(@NonNull Runnable runnable) {
        return this.f2139f.submit(runnable);
    }

    public String toString() {
        return this.f2139f.toString();
    }

    @Override // java.util.concurrent.ExecutorService
    @NonNull
    public <T> List<Future<T>> invokeAll(@NonNull Collection<? extends Callable<T>> collection, long j2, @NonNull TimeUnit timeUnit) {
        return this.f2139f.invokeAll(collection, j2, timeUnit);
    }

    @Override // java.util.concurrent.ExecutorService
    public <T> T invokeAny(@NonNull Collection<? extends Callable<T>> collection, long j2, @NonNull TimeUnit timeUnit) {
        return (T) this.f2139f.invokeAny(collection, j2, timeUnit);
    }

    @Override // java.util.concurrent.ExecutorService
    @NonNull
    public <T> Future<T> submit(@NonNull Runnable runnable, T t) {
        return this.f2139f.submit(runnable, t);
    }

    @Override // java.util.concurrent.ExecutorService
    public <T> Future<T> submit(@NonNull Callable<T> callable) {
        return this.f2139f.submit(callable);
    }
}
