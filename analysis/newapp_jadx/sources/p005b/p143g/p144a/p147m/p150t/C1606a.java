package p005b.p143g.p144a.p147m.p150t;

import android.os.Process;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.C1649q;

/* renamed from: b.g.a.m.t.a */
/* loaded from: classes.dex */
public final class C1606a {

    /* renamed from: a */
    public final boolean f2040a;

    /* renamed from: b */
    @VisibleForTesting
    public final Map<InterfaceC1579k, b> f2041b;

    /* renamed from: c */
    public final ReferenceQueue<C1649q<?>> f2042c;

    /* renamed from: d */
    public C1649q.a f2043d;

    /* renamed from: b.g.a.m.t.a$a */
    public class a implements ThreadFactory {

        /* renamed from: b.g.a.m.t.a$a$a, reason: collision with other inner class name */
        public class RunnableC5106a implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ Runnable f2044c;

            public RunnableC5106a(a aVar, Runnable runnable) {
                this.f2044c = runnable;
            }

            @Override // java.lang.Runnable
            public void run() {
                Process.setThreadPriority(10);
                this.f2044c.run();
            }
        }

        @Override // java.util.concurrent.ThreadFactory
        public Thread newThread(@NonNull Runnable runnable) {
            return new Thread(new RunnableC5106a(this, runnable), "glide-active-resources");
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.t.a$b */
    public static final class b extends WeakReference<C1649q<?>> {

        /* renamed from: a */
        public final InterfaceC1579k f2045a;

        /* renamed from: b */
        public final boolean f2046b;

        /* renamed from: c */
        @Nullable
        public InterfaceC1655w<?> f2047c;

        public b(@NonNull InterfaceC1579k interfaceC1579k, @NonNull C1649q<?> c1649q, @NonNull ReferenceQueue<? super C1649q<?>> referenceQueue, boolean z) {
            super(c1649q, referenceQueue);
            InterfaceC1655w<?> interfaceC1655w;
            Objects.requireNonNull(interfaceC1579k, "Argument must not be null");
            this.f2045a = interfaceC1579k;
            if (c1649q.f2293c && z) {
                interfaceC1655w = c1649q.f2295f;
                Objects.requireNonNull(interfaceC1655w, "Argument must not be null");
            } else {
                interfaceC1655w = null;
            }
            this.f2047c = interfaceC1655w;
            this.f2046b = c1649q.f2293c;
        }
    }

    public C1606a(boolean z) {
        ExecutorService newSingleThreadExecutor = Executors.newSingleThreadExecutor(new a());
        this.f2041b = new HashMap();
        this.f2042c = new ReferenceQueue<>();
        this.f2040a = z;
        newSingleThreadExecutor.execute(new RunnableC1608b(this));
    }

    /* renamed from: a */
    public synchronized void m851a(InterfaceC1579k interfaceC1579k, C1649q<?> c1649q) {
        b put = this.f2041b.put(interfaceC1579k, new b(interfaceC1579k, c1649q, this.f2042c, this.f2040a));
        if (put != null) {
            put.f2047c = null;
            put.clear();
        }
    }

    /* renamed from: b */
    public void m852b(@NonNull b bVar) {
        InterfaceC1655w<?> interfaceC1655w;
        synchronized (this) {
            this.f2041b.remove(bVar.f2045a);
            if (bVar.f2046b && (interfaceC1655w = bVar.f2047c) != null) {
                this.f2043d.mo932a(bVar.f2045a, new C1649q<>(interfaceC1655w, true, false, bVar.f2045a, this.f2043d));
            }
        }
    }
}
