package p005b.p139f.p140a.p142b;

import android.os.Handler;
import android.os.Looper;
import androidx.annotation.NonNull;
import java.lang.Thread;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.f.a.b.j */
/* loaded from: classes.dex */
public final class C1540j {

    /* renamed from: a */
    public static final Handler f1772a = new Handler(Looper.getMainLooper());

    /* renamed from: b */
    public static final Map<Integer, Map<Integer, ExecutorService>> f1773b = new HashMap();

    /* renamed from: c */
    public static final int f1774c;

    /* renamed from: b.f.a.b.j$b */
    public static final class b extends ThreadPoolExecutor {

        /* renamed from: c */
        public final AtomicInteger f1777c;

        /* renamed from: e */
        public a f1778e;

        public b(int i2, int i3, long j2, TimeUnit timeUnit, a aVar, ThreadFactory threadFactory) {
            super(i2, i3, j2, timeUnit, aVar, threadFactory);
            this.f1777c = new AtomicInteger();
            aVar.f1775c = this;
            this.f1778e = aVar;
        }

        /* renamed from: a */
        public static ExecutorService m713a(int i2, int i3) {
            if (i2 == -8) {
                int i4 = C1540j.f1774c;
                return new b(i4 + 1, (i4 * 2) + 1, 30L, TimeUnit.SECONDS, new a(true), new c("cpu", i3));
            }
            if (i2 != -4) {
                return i2 != -2 ? i2 != -1 ? new b(i2, i2, 0L, TimeUnit.MILLISECONDS, new a(), new c(C1499a.m628n("fixed(", i2, ChineseToPinyinResource.Field.RIGHT_BRACKET), i3)) : new b(1, 1, 0L, TimeUnit.MILLISECONDS, new a(), new c("single", i3)) : new b(0, 128, 60L, TimeUnit.SECONDS, new a(true), new c("cached", i3));
            }
            int i5 = (C1540j.f1774c * 2) + 1;
            return new b(i5, i5, 30L, TimeUnit.SECONDS, new a(), new c("io", i3));
        }

        @Override // java.util.concurrent.ThreadPoolExecutor
        public void afterExecute(Runnable runnable, Throwable th) {
            this.f1777c.decrementAndGet();
            super.afterExecute(runnable, th);
        }

        @Override // java.util.concurrent.ThreadPoolExecutor, java.util.concurrent.Executor
        public void execute(@NonNull Runnable runnable) {
            if (isShutdown()) {
                return;
            }
            this.f1777c.incrementAndGet();
            try {
                super.execute(runnable);
            } catch (RejectedExecutionException unused) {
                this.f1778e.offer(runnable);
            } catch (Throwable unused2) {
                this.f1777c.decrementAndGet();
            }
        }
    }

    /* renamed from: b.f.a.b.j$c */
    public static final class c extends AtomicLong implements ThreadFactory {

        /* renamed from: c */
        public static final AtomicInteger f1779c = new AtomicInteger(1);
        private static final long serialVersionUID = -9209200509960368598L;

        /* renamed from: e */
        public final String f1780e;

        /* renamed from: f */
        public final int f1781f;

        /* renamed from: b.f.a.b.j$c$a */
        public class a extends Thread {
            public a(c cVar, Runnable runnable, String str) {
                super(runnable, str);
            }

            @Override // java.lang.Thread, java.lang.Runnable
            public void run() {
                try {
                    super.run();
                } catch (Throwable unused) {
                }
            }
        }

        /* renamed from: b.f.a.b.j$c$b */
        public class b implements Thread.UncaughtExceptionHandler {
            public b(c cVar) {
            }

            @Override // java.lang.Thread.UncaughtExceptionHandler
            public void uncaughtException(Thread thread, Throwable th) {
                System.out.println(th);
            }
        }

        public c(String str, int i2) {
            StringBuilder m590L = C1499a.m590L(str, "-pool-");
            m590L.append(f1779c.getAndIncrement());
            m590L.append("-thread-");
            this.f1780e = m590L.toString();
            this.f1781f = i2;
        }

        @Override // java.util.concurrent.ThreadFactory
        public Thread newThread(@NonNull Runnable runnable) {
            a aVar = new a(this, runnable, this.f1780e + getAndIncrement());
            aVar.setDaemon(false);
            aVar.setUncaughtExceptionHandler(new b(this));
            aVar.setPriority(this.f1781f);
            return aVar;
        }
    }

    static {
        new ConcurrentHashMap();
        f1774c = Runtime.getRuntime().availableProcessors();
        new Timer();
    }

    /* renamed from: b.f.a.b.j$a */
    public static final class a extends LinkedBlockingQueue<Runnable> {

        /* renamed from: c */
        public volatile b f1775c;

        /* renamed from: e */
        public int f1776e;

        public a() {
            this.f1776e = Integer.MAX_VALUE;
        }

        @Override // java.util.concurrent.LinkedBlockingQueue, java.util.Queue, java.util.concurrent.BlockingQueue
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public boolean offer(@NonNull Runnable runnable) {
            if (this.f1776e > size() || this.f1775c == null || this.f1775c.getPoolSize() >= this.f1775c.getMaximumPoolSize()) {
                return super.offer(runnable);
            }
            return false;
        }

        public a(boolean z) {
            this.f1776e = Integer.MAX_VALUE;
            if (z) {
                this.f1776e = 0;
            }
        }
    }
}
