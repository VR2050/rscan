package com.ding.rtc.task;

import java.util.Comparator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/* JADX INFO: loaded from: classes.dex */
public class TaskThreadPoolExecutor extends ThreadPoolExecutor {
    private static final int CORE_POOL_SIZE = 3;
    private static final int KEEP_ALIVE = 60;
    private static final int MAXIMUM_POOL_SIZE = 16;
    private static final AtomicLong SEQ_SEED = new AtomicLong(0);
    private static final ThreadFactory sThreadFactory = new ThreadFactory() { // from class: com.ding.rtc.task.TaskThreadPoolExecutor.1
        private final AtomicInteger mCount = new AtomicInteger(1);

        @Override // java.util.concurrent.ThreadFactory
        public Thread newThread(Runnable runnable) {
            return new Thread(runnable, "DingRtcTaskThreadPoolExecutor#" + this.mCount.getAndIncrement());
        }
    };
    private static final Comparator<Runnable> FIFO = new Comparator<Runnable>() { // from class: com.ding.rtc.task.TaskThreadPoolExecutor.2
        @Override // java.util.Comparator
        public int compare(Runnable lhs, Runnable rhs) {
            if ((lhs instanceof SimpleTask) && (rhs instanceof SimpleTask)) {
                SimpleTask lpr = (SimpleTask) lhs;
                SimpleTask rpr = (SimpleTask) rhs;
                int result = lpr.priority.ordinal() - rpr.priority.ordinal();
                return result == 0 ? (int) (lpr.SEQ - rpr.SEQ) : result;
            }
            return 0;
        }
    };
    private static final Comparator<Runnable> LIFO = new Comparator<Runnable>() { // from class: com.ding.rtc.task.TaskThreadPoolExecutor.3
        @Override // java.util.Comparator
        public int compare(Runnable lhs, Runnable rhs) {
            if ((lhs instanceof SimpleTask) && (rhs instanceof SimpleTask)) {
                SimpleTask lpr = (SimpleTask) lhs;
                SimpleTask rpr = (SimpleTask) rhs;
                int result = lpr.priority.ordinal() - rpr.priority.ordinal();
                return result == 0 ? (int) (rpr.SEQ - lpr.SEQ) : result;
            }
            return 0;
        }
    };

    public TaskThreadPoolExecutor(boolean fifo) {
        this(3, fifo);
    }

    public TaskThreadPoolExecutor(int poolSize, boolean fifo) {
        this(poolSize, 16, 60L, TimeUnit.SECONDS, new PriorityBlockingQueue(16, fifo ? FIFO : LIFO), sThreadFactory);
    }

    public TaskThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue, threadFactory);
    }

    public boolean isBusy() {
        return getActiveCount() >= getCorePoolSize();
    }

    @Override // java.util.concurrent.ThreadPoolExecutor, java.util.concurrent.Executor
    public void execute(Runnable runnable) {
        if (runnable instanceof SimpleTask) {
            ((SimpleTask) runnable).SEQ = SEQ_SEED.getAndIncrement();
        }
        super.execute(runnable);
    }
}
