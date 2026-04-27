package V;

import android.os.Handler;
import android.os.Looper;

/* JADX INFO: loaded from: classes.dex */
public class f extends b {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static f f2809c;

    private f() {
        super(new Handler(Looper.getMainLooper()));
    }

    public static f h() {
        if (f2809c == null) {
            f2809c = new f();
        }
        return f2809c;
    }

    @Override // V.b, java.util.concurrent.Executor
    public void execute(Runnable runnable) {
        if (b()) {
            runnable.run();
        } else {
            super.execute(runnable);
        }
    }
}
