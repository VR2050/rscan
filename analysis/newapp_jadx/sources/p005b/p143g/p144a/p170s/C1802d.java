package p005b.p143g.p144a.p170s;

import android.os.Handler;
import android.os.Looper;
import androidx.annotation.NonNull;
import java.util.concurrent.Executor;

/* renamed from: b.g.a.s.d */
/* loaded from: classes.dex */
public final class C1802d {

    /* renamed from: a */
    public static final Executor f2755a = new a();

    /* renamed from: b */
    public static final Executor f2756b = new b();

    /* renamed from: b.g.a.s.d$a */
    public class a implements Executor {

        /* renamed from: c */
        public final Handler f2757c = new Handler(Looper.getMainLooper());

        @Override // java.util.concurrent.Executor
        public void execute(@NonNull Runnable runnable) {
            this.f2757c.post(runnable);
        }
    }

    /* renamed from: b.g.a.s.d$b */
    public class b implements Executor {
        @Override // java.util.concurrent.Executor
        public void execute(@NonNull Runnable runnable) {
            runnable.run();
        }
    }
}
