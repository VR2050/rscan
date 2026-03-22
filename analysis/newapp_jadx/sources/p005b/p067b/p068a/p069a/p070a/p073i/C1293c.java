package p005b.p067b.p068a.p069a.p070a.p073i;

import android.os.Handler;
import android.os.Looper;
import androidx.recyclerview.widget.ListUpdateCallback;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.diff.BrvahListUpdateCallback;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.b.a.a.a.i.c */
/* loaded from: classes.dex */
public final class C1293c<T> {

    /* renamed from: a */
    @NotNull
    public final BaseQuickAdapter<T, ?> f1017a;

    /* renamed from: b */
    @NotNull
    public final C1294d<T> f1018b;

    /* renamed from: c */
    @NotNull
    public final ListUpdateCallback f1019c;

    /* renamed from: d */
    @NotNull
    public Executor f1020d;

    /* renamed from: e */
    @NotNull
    public final Executor f1021e;

    /* renamed from: f */
    @NotNull
    public final List<InterfaceC1295e<T>> f1022f;

    /* renamed from: g */
    public int f1023g;

    /* renamed from: b.b.a.a.a.i.c$a */
    public static final class a implements Executor {

        /* renamed from: c */
        @NotNull
        public final Handler f1024c = new Handler(Looper.getMainLooper());

        @Override // java.util.concurrent.Executor
        public void execute(@NotNull Runnable command) {
            Intrinsics.checkNotNullParameter(command, "command");
            this.f1024c.post(command);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.util.concurrent.Executor] */
    public C1293c(@NotNull BaseQuickAdapter<T, ?> adapter, @NotNull C1294d<T> config) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(config, "config");
        this.f1017a = adapter;
        this.f1018b = config;
        this.f1019c = new BrvahListUpdateCallback(adapter);
        a aVar = new a();
        this.f1021e = aVar;
        ?? r3 = config.f1025a;
        this.f1020d = r3 != 0 ? r3 : aVar;
        this.f1022f = new CopyOnWriteArrayList();
    }

    /* renamed from: a */
    public final void m308a(List<? extends T> list, Runnable runnable) {
        Iterator<InterfaceC1295e<T>> it = this.f1022f.iterator();
        while (it.hasNext()) {
            it.next().onCurrentListChanged(list, this.f1017a.getData());
        }
        if (runnable == null) {
            return;
        }
        runnable.run();
    }
}
