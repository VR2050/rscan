package o0;

import android.os.Looper;

/* JADX INFO: renamed from: o0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0637a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static AbstractC0637a f9687a;

    /* JADX INFO: renamed from: o0.a$a, reason: collision with other inner class name */
    public interface InterfaceC0141a {
        void a();
    }

    public static synchronized AbstractC0637a b() {
        try {
            if (f9687a == null) {
                f9687a = new b();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f9687a;
    }

    static boolean c() {
        return Looper.getMainLooper().getThread() == Thread.currentThread();
    }

    public abstract void a(InterfaceC0141a interfaceC0141a);

    public abstract void d(InterfaceC0141a interfaceC0141a);
}
