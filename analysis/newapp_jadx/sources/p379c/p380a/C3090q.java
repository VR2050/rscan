package p379c.p380a;

import java.lang.reflect.Method;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.coroutines.CoroutineContext;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.text.StringsKt__StringNumberConversionsKt;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.q */
/* loaded from: classes2.dex */
public final class C3090q extends AbstractC3106v0 {

    /* renamed from: c */
    public static final int f8437c;

    /* renamed from: e */
    public static final C3090q f8438e = new C3090q();
    public static volatile Executor pool;

    /* renamed from: c.a.q$a */
    public static final class a implements ThreadFactory {

        /* renamed from: c */
        public final /* synthetic */ AtomicInteger f8439c;

        public a(AtomicInteger atomicInteger) {
            this.f8439c = atomicInteger;
        }

        @Override // java.util.concurrent.ThreadFactory
        public final Thread newThread(Runnable runnable) {
            StringBuilder m586H = C1499a.m586H("CommonPool-worker-");
            m586H.append(this.f8439c.incrementAndGet());
            Thread thread = new Thread(runnable, m586H.toString());
            thread.setDaemon(true);
            return thread;
        }
    }

    static {
        String str;
        int i2;
        try {
            str = System.getProperty("kotlinx.coroutines.default.parallelism");
        } catch (Throwable unused) {
            str = null;
        }
        if (str != null) {
            Integer intOrNull = StringsKt__StringNumberConversionsKt.toIntOrNull(str);
            if (intOrNull == null || intOrNull.intValue() < 1) {
                throw new IllegalStateException(C1499a.m637w("Expected positive number in kotlinx.coroutines.default.parallelism, but has ", str).toString());
            }
            i2 = intOrNull.intValue();
        } else {
            i2 = -1;
        }
        f8437c = i2;
    }

    /* renamed from: U */
    public final ExecutorService m3623U() {
        return Executors.newFixedThreadPool(m3625W(), new a(new AtomicInteger()));
    }

    /* renamed from: V */
    public final ExecutorService m3624V() {
        Class<?> cls;
        ExecutorService executorService;
        Integer num;
        if (System.getSecurityManager() != null) {
            return m3623U();
        }
        ExecutorService executorService2 = null;
        try {
            cls = Class.forName("java.util.concurrent.ForkJoinPool");
        } catch (Throwable unused) {
            cls = null;
        }
        if (cls == null) {
            return m3623U();
        }
        if (f8437c < 0) {
            try {
                Method method = cls.getMethod("commonPool", new Class[0]);
                Object invoke = method != null ? method.invoke(null, new Object[0]) : null;
                if (!(invoke instanceof ExecutorService)) {
                    invoke = null;
                }
                executorService = (ExecutorService) invoke;
            } catch (Throwable unused2) {
                executorService = null;
            }
            if (executorService != null) {
                Objects.requireNonNull(f8438e);
                executorService.submit(RunnableC3093r.f8445c);
                try {
                    Object invoke2 = cls.getMethod("getPoolSize", new Class[0]).invoke(executorService, new Object[0]);
                    if (!(invoke2 instanceof Integer)) {
                        invoke2 = null;
                    }
                    num = (Integer) invoke2;
                } catch (Throwable unused3) {
                    num = null;
                }
                if (!(num != null && num.intValue() >= 1)) {
                    executorService = null;
                }
                if (executorService != null) {
                    return executorService;
                }
            }
        }
        try {
            Object newInstance = cls.getConstructor(Integer.TYPE).newInstance(Integer.valueOf(f8438e.m3625W()));
            if (!(newInstance instanceof ExecutorService)) {
                newInstance = null;
            }
            executorService2 = (ExecutorService) newInstance;
        } catch (Throwable unused4) {
        }
        return executorService2 != null ? executorService2 : m3623U();
    }

    /* renamed from: W */
    public final int m3625W() {
        Integer valueOf = Integer.valueOf(f8437c);
        if (!(valueOf.intValue() > 0)) {
            valueOf = null;
        }
        return valueOf != null ? valueOf.intValue() : RangesKt___RangesKt.coerceAtLeast(Runtime.getRuntime().availableProcessors() - 1, 1);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        throw new IllegalStateException("Close cannot be invoked on CommonPool".toString());
    }

    @Override // p379c.p380a.AbstractC3036c0
    public void dispatch(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        try {
            Executor executor = pool;
            if (executor == null) {
                synchronized (this) {
                    executor = pool;
                    if (executor == null) {
                        executor = m3624V();
                        pool = executor;
                    }
                }
            }
            executor.execute(runnable);
        } catch (RejectedExecutionException unused) {
            RunnableC3061g0.f8400k.m3633c0(runnable);
        }
    }

    @Override // p379c.p380a.AbstractC3036c0
    @NotNull
    public String toString() {
        return "CommonPool";
    }
}
