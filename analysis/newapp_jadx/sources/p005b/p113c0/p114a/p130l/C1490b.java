package p005b.p113c0.p114a.p130l;

import android.os.Handler;
import android.os.Looper;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* renamed from: b.c0.a.l.b */
/* loaded from: classes2.dex */
public class C1490b {

    /* renamed from: a */
    public static C1490b f1496a;

    /* renamed from: b */
    public static Handler f1497b;

    /* renamed from: c */
    public final ExecutorService f1498c = Executors.newCachedThreadPool();

    public C1490b() {
        f1497b = new Handler(Looper.getMainLooper());
    }

    /* renamed from: a */
    public static C1490b m560a() {
        if (f1496a == null) {
            synchronized (C1490b.class) {
                if (f1496a == null) {
                    f1496a = new C1490b();
                }
            }
        }
        return f1496a;
    }
}
