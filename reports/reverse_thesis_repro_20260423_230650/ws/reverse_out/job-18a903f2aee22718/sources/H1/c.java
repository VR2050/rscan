package H1;

import com.facebook.react.bridge.UiThreadUtil;
import java.util.concurrent.Executor;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final c f1031a = new c();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final Executor f1032b = new b();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final Executor f1033c = new a();

    private static final class a implements Executor {
        @Override // java.util.concurrent.Executor
        public void execute(Runnable runnable) {
            j.f(runnable, "command");
            runnable.run();
        }
    }

    private static final class b implements Executor {
        @Override // java.util.concurrent.Executor
        public void execute(Runnable runnable) {
            j.f(runnable, "command");
            UiThreadUtil.runOnUiThread(runnable);
        }
    }

    private c() {
    }
}
