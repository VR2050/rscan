package p476m.p477a.p485b.p488j0.p489h;

import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* renamed from: m.a.b.j0.h.g */
/* loaded from: classes3.dex */
public class C4826g extends ThreadPoolExecutor {

    /* renamed from: c */
    public final Map<RunnableC4825f, Boolean> f12361c;

    public C4826g(int i2, int i3, long j2, TimeUnit timeUnit, BlockingQueue<Runnable> blockingQueue, ThreadFactory threadFactory) {
        super(i2, i3, j2, timeUnit, blockingQueue, threadFactory);
        this.f12361c = new ConcurrentHashMap();
    }

    @Override // java.util.concurrent.ThreadPoolExecutor
    public void afterExecute(Runnable runnable, Throwable th) {
        if (runnable instanceof RunnableC4825f) {
            this.f12361c.remove(runnable);
        }
    }

    @Override // java.util.concurrent.ThreadPoolExecutor
    public void beforeExecute(Thread thread, Runnable runnable) {
        if (runnable instanceof RunnableC4825f) {
            this.f12361c.put((RunnableC4825f) runnable, Boolean.TRUE);
        }
    }
}
