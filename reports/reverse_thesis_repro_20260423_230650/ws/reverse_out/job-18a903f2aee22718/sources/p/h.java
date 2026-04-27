package p;

import android.os.Handler;
import android.os.Process;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import q.InterfaceC0651a;

/* JADX INFO: loaded from: classes.dex */
abstract class h {

    private static class a implements ThreadFactory {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private String f9774a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f9775b;

        /* JADX INFO: renamed from: p.h$a$a, reason: collision with other inner class name */
        private static class C0144a extends Thread {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            private final int f9776b;

            C0144a(Runnable runnable, String str, int i3) {
                super(runnable, str);
                this.f9776b = i3;
            }

            @Override // java.lang.Thread, java.lang.Runnable
            public void run() {
                Process.setThreadPriority(this.f9776b);
                super.run();
            }
        }

        a(String str, int i3) {
            this.f9774a = str;
            this.f9775b = i3;
        }

        @Override // java.util.concurrent.ThreadFactory
        public Thread newThread(Runnable runnable) {
            return new C0144a(runnable, this.f9774a, this.f9775b);
        }
    }

    private static class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private Callable f9777b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private InterfaceC0651a f9778c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private Handler f9779d;

        class a implements Runnable {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ InterfaceC0651a f9780b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ Object f9781c;

            a(InterfaceC0651a interfaceC0651a, Object obj) {
                this.f9780b = interfaceC0651a;
                this.f9781c = obj;
            }

            @Override // java.lang.Runnable
            public void run() {
                this.f9780b.a(this.f9781c);
            }
        }

        b(Handler handler, Callable callable, InterfaceC0651a interfaceC0651a) {
            this.f9777b = callable;
            this.f9778c = interfaceC0651a;
            this.f9779d = handler;
        }

        @Override // java.lang.Runnable
        public void run() {
            Object objCall;
            try {
                objCall = this.f9777b.call();
            } catch (Exception unused) {
                objCall = null;
            }
            this.f9779d.post(new a(this.f9778c, objCall));
        }
    }

    static ThreadPoolExecutor a(String str, int i3, int i4) {
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(0, 1, i4, TimeUnit.MILLISECONDS, new LinkedBlockingDeque(), new a(str, i3));
        threadPoolExecutor.allowCoreThreadTimeOut(true);
        return threadPoolExecutor;
    }

    static void b(Executor executor, Callable callable, InterfaceC0651a interfaceC0651a) {
        executor.execute(new b(p.b.a(), callable, interfaceC0651a));
    }

    static Object c(ExecutorService executorService, Callable callable, int i3) throws InterruptedException {
        try {
            return executorService.submit(callable).get(i3, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e3) {
            throw e3;
        } catch (ExecutionException e4) {
            throw new RuntimeException(e4);
        } catch (TimeoutException unused) {
            throw new InterruptedException("timeout");
        }
    }
}
