package I0;

import android.os.Process;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes.dex */
public final class B implements ThreadFactory {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f1105a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f1106b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f1107c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final AtomicInteger f1108d;

    public B(int i3, String str, boolean z3) {
        t2.j.f(str, "prefix");
        this.f1105a = i3;
        this.f1106b = str;
        this.f1107c = z3;
        this.f1108d = new AtomicInteger(1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void b(B b3, Runnable runnable) {
        t2.j.f(b3, "this$0");
        t2.j.f(runnable, "$runnable");
        try {
            Process.setThreadPriority(b3.f1105a);
        } catch (Throwable unused) {
        }
        runnable.run();
    }

    @Override // java.util.concurrent.ThreadFactory
    public Thread newThread(final Runnable runnable) {
        String str;
        t2.j.f(runnable, "runnable");
        Runnable runnable2 = new Runnable() { // from class: I0.A
            @Override // java.lang.Runnable
            public final void run() {
                B.b(this.f1103b, runnable);
            }
        };
        if (this.f1107c) {
            str = this.f1106b + "-" + this.f1108d.getAndIncrement();
        } else {
            str = this.f1106b;
        }
        return new Thread(runnable2, str);
    }
}
