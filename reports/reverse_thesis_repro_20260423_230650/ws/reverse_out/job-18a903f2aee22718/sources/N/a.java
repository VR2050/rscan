package N;

import android.os.Handler;
import android.os.Looper;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
final class a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final a f1837b = new a();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final int f1838c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    static final int f1839d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    static final int f1840e;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f1841a = new b();

    private static class b implements Executor {
        private b() {
        }

        @Override // java.util.concurrent.Executor
        public void execute(Runnable runnable) {
            new Handler(Looper.getMainLooper()).post(runnable);
        }
    }

    static {
        int iAvailableProcessors = Runtime.getRuntime().availableProcessors();
        f1838c = iAvailableProcessors;
        f1839d = iAvailableProcessors + 1;
        f1840e = (iAvailableProcessors * 2) + 1;
    }

    private a() {
    }

    public static void a(ThreadPoolExecutor threadPoolExecutor, boolean z3) {
        threadPoolExecutor.allowCoreThreadTimeOut(z3);
    }

    public static ExecutorService b() {
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(f1839d, f1840e, 1L, TimeUnit.SECONDS, new LinkedBlockingQueue());
        a(threadPoolExecutor, true);
        return threadPoolExecutor;
    }

    public static Executor c() {
        return f1837b.f1841a;
    }
}
