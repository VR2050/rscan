package p476m.p477a.p485b.p488j0.p489h;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/* renamed from: m.a.b.j0.h.e */
/* loaded from: classes3.dex */
public class ThreadFactoryC4824e implements ThreadFactory {

    /* renamed from: c */
    public final String f12355c;

    /* renamed from: e */
    public final ThreadGroup f12356e;

    /* renamed from: f */
    public final AtomicLong f12357f;

    public ThreadFactoryC4824e(String str) {
        this.f12355c = str;
        this.f12356e = null;
        this.f12357f = new AtomicLong();
    }

    @Override // java.util.concurrent.ThreadFactory
    public Thread newThread(Runnable runnable) {
        return new Thread(this.f12356e, runnable, this.f12355c + "-" + this.f12357f.incrementAndGet());
    }

    public ThreadFactoryC4824e(String str, ThreadGroup threadGroup) {
        this.f12355c = str;
        this.f12356e = threadGroup;
        this.f12357f = new AtomicLong();
    }
}
