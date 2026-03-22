package p458k.p459p0.p461e;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.Unit;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.p459p0.C4401c;
import p458k.p459p0.ThreadFactoryC4400b;

/* renamed from: k.p0.e.c */
/* loaded from: classes3.dex */
public final class C4410c {

    /* renamed from: a */
    @JvmField
    @NotNull
    public static final C4410c f11626a;

    /* renamed from: b */
    @NotNull
    public static final Logger f11627b;

    /* renamed from: c */
    public static final b f11628c = new b(null);

    /* renamed from: d */
    public int f11629d;

    /* renamed from: e */
    public boolean f11630e;

    /* renamed from: f */
    public long f11631f;

    /* renamed from: g */
    public final List<C4409b> f11632g;

    /* renamed from: h */
    public final List<C4409b> f11633h;

    /* renamed from: i */
    public final Runnable f11634i;

    /* renamed from: j */
    @NotNull
    public final a f11635j;

    /* renamed from: k.p0.e.c$a */
    public interface a {
        /* renamed from: a */
        void mo5079a(@NotNull C4410c c4410c);

        /* renamed from: b */
        void mo5080b(@NotNull C4410c c4410c, long j2);

        /* renamed from: c */
        long mo5081c();

        void execute(@NotNull Runnable runnable);
    }

    /* renamed from: k.p0.e.c$b */
    public static final class b {
        public b(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    /* renamed from: k.p0.e.c$c */
    public static final class c implements a {

        /* renamed from: a */
        public final ThreadPoolExecutor f11636a;

        public c(@NotNull ThreadFactory threadFactory) {
            Intrinsics.checkParameterIsNotNull(threadFactory, "threadFactory");
            this.f11636a = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 60L, TimeUnit.SECONDS, new SynchronousQueue(), threadFactory);
        }

        @Override // p458k.p459p0.p461e.C4410c.a
        /* renamed from: a */
        public void mo5079a(@NotNull C4410c taskRunner) {
            Intrinsics.checkParameterIsNotNull(taskRunner, "taskRunner");
            taskRunner.notify();
        }

        @Override // p458k.p459p0.p461e.C4410c.a
        /* renamed from: b */
        public void mo5080b(@NotNull C4410c taskRunner, long j2) {
            Intrinsics.checkParameterIsNotNull(taskRunner, "taskRunner");
            long j3 = j2 / 1000000;
            long j4 = j2 - (1000000 * j3);
            if (j3 > 0 || j2 > 0) {
                taskRunner.wait(j3, (int) j4);
            }
        }

        @Override // p458k.p459p0.p461e.C4410c.a
        /* renamed from: c */
        public long mo5081c() {
            return System.nanoTime();
        }

        @Override // p458k.p459p0.p461e.C4410c.a
        public void execute(@NotNull Runnable runnable) {
            Intrinsics.checkParameterIsNotNull(runnable, "runnable");
            this.f11636a.execute(runnable);
        }
    }

    /* renamed from: k.p0.e.c$d */
    public static final class d implements Runnable {
        public d() {
        }

        @Override // java.lang.Runnable
        public void run() {
            AbstractC4408a m5075c;
            while (true) {
                synchronized (C4410c.this) {
                    m5075c = C4410c.this.m5075c();
                }
                if (m5075c == null) {
                    return;
                }
                C4409b c4409b = m5075c.f11616a;
                if (c4409b == null) {
                    Intrinsics.throwNpe();
                }
                long j2 = -1;
                b bVar = C4410c.f11628c;
                boolean isLoggable = C4410c.f11627b.isLoggable(Level.FINE);
                if (isLoggable) {
                    j2 = c4409b.f11624e.f11635j.mo5081c();
                    C2354n.m2464d(m5075c, c4409b, "starting");
                }
                try {
                    try {
                        C4410c.m5073a(C4410c.this, m5075c);
                        Unit unit = Unit.INSTANCE;
                        if (isLoggable) {
                            long mo5081c = c4409b.f11624e.f11635j.mo5081c() - j2;
                            StringBuilder m586H = C1499a.m586H("finished run in ");
                            m586H.append(C2354n.m2473f0(mo5081c));
                            C2354n.m2464d(m5075c, c4409b, m586H.toString());
                        }
                    } finally {
                    }
                } catch (Throwable th) {
                    if (isLoggable) {
                        long mo5081c2 = c4409b.f11624e.f11635j.mo5081c() - j2;
                        StringBuilder m586H2 = C1499a.m586H("failed a run in ");
                        m586H2.append(C2354n.m2473f0(mo5081c2));
                        C2354n.m2464d(m5075c, c4409b, m586H2.toString());
                    }
                    throw th;
                }
            }
        }
    }

    static {
        byte[] bArr = C4401c.f11556a;
        Intrinsics.checkParameterIsNotNull("OkHttp TaskRunner", "name");
        f11626a = new C4410c(new c(new ThreadFactoryC4400b("OkHttp TaskRunner", true)));
        Logger logger = Logger.getLogger(C4410c.class.getName());
        Intrinsics.checkExpressionValueIsNotNull(logger, "Logger.getLogger(TaskRunner::class.java.name)");
        f11627b = logger;
    }

    public C4410c(@NotNull a backend) {
        Intrinsics.checkParameterIsNotNull(backend, "backend");
        this.f11635j = backend;
        this.f11629d = 10000;
        this.f11632g = new ArrayList();
        this.f11633h = new ArrayList();
        this.f11634i = new d();
    }

    /* renamed from: a */
    public static final void m5073a(C4410c c4410c, AbstractC4408a abstractC4408a) {
        Objects.requireNonNull(c4410c);
        byte[] bArr = C4401c.f11556a;
        Thread currentThread = Thread.currentThread();
        Intrinsics.checkExpressionValueIsNotNull(currentThread, "currentThread");
        String name = currentThread.getName();
        currentThread.setName(abstractC4408a.f11618c);
        try {
            long mo5066a = abstractC4408a.mo5066a();
            synchronized (c4410c) {
                c4410c.m5074b(abstractC4408a, mo5066a);
                Unit unit = Unit.INSTANCE;
            }
            currentThread.setName(name);
        } catch (Throwable th) {
            synchronized (c4410c) {
                c4410c.m5074b(abstractC4408a, -1L);
                Unit unit2 = Unit.INSTANCE;
                currentThread.setName(name);
                throw th;
            }
        }
    }

    /* renamed from: b */
    public final void m5074b(AbstractC4408a abstractC4408a, long j2) {
        byte[] bArr = C4401c.f11556a;
        C4409b c4409b = abstractC4408a.f11616a;
        if (c4409b == null) {
            Intrinsics.throwNpe();
        }
        if (!(c4409b.f11621b == abstractC4408a)) {
            throw new IllegalStateException("Check failed.".toString());
        }
        boolean z = c4409b.f11623d;
        c4409b.f11623d = false;
        c4409b.f11621b = null;
        this.f11632g.remove(c4409b);
        if (j2 != -1 && !z && !c4409b.f11620a) {
            c4409b.m5071e(abstractC4408a, j2, true);
        }
        if (!c4409b.f11622c.isEmpty()) {
            this.f11633h.add(c4409b);
        }
    }

    @Nullable
    /* renamed from: c */
    public final AbstractC4408a m5075c() {
        boolean z;
        byte[] bArr = C4401c.f11556a;
        while (!this.f11633h.isEmpty()) {
            long mo5081c = this.f11635j.mo5081c();
            long j2 = Long.MAX_VALUE;
            Iterator<C4409b> it = this.f11633h.iterator();
            AbstractC4408a abstractC4408a = null;
            while (true) {
                if (!it.hasNext()) {
                    z = false;
                    break;
                }
                AbstractC4408a abstractC4408a2 = it.next().f11622c.get(0);
                long max = Math.max(0L, abstractC4408a2.f11617b - mo5081c);
                if (max > 0) {
                    j2 = Math.min(max, j2);
                } else {
                    if (abstractC4408a != null) {
                        z = true;
                        break;
                    }
                    abstractC4408a = abstractC4408a2;
                }
            }
            if (abstractC4408a != null) {
                byte[] bArr2 = C4401c.f11556a;
                abstractC4408a.f11617b = -1L;
                C4409b c4409b = abstractC4408a.f11616a;
                if (c4409b == null) {
                    Intrinsics.throwNpe();
                }
                c4409b.f11622c.remove(abstractC4408a);
                this.f11633h.remove(c4409b);
                c4409b.f11621b = abstractC4408a;
                this.f11632g.add(c4409b);
                if (z || (!this.f11630e && (!this.f11633h.isEmpty()))) {
                    this.f11635j.execute(this.f11634i);
                }
                return abstractC4408a;
            }
            if (this.f11630e) {
                if (j2 < this.f11631f - mo5081c) {
                    this.f11635j.mo5079a(this);
                }
                return null;
            }
            this.f11630e = true;
            this.f11631f = mo5081c + j2;
            try {
                try {
                    this.f11635j.mo5080b(this, j2);
                } catch (InterruptedException unused) {
                    m5076d();
                }
            } finally {
                this.f11630e = false;
            }
        }
        return null;
    }

    /* renamed from: d */
    public final void m5076d() {
        for (int size = this.f11632g.size() - 1; size >= 0; size--) {
            this.f11633h.get(size).m5069b();
        }
        for (int size2 = this.f11633h.size() - 1; size2 >= 0; size2--) {
            C4409b c4409b = this.f11633h.get(size2);
            c4409b.m5069b();
            if (c4409b.f11622c.isEmpty()) {
                this.f11633h.remove(size2);
            }
        }
    }

    /* renamed from: e */
    public final void m5077e(@NotNull C4409b taskQueue) {
        Intrinsics.checkParameterIsNotNull(taskQueue, "taskQueue");
        byte[] bArr = C4401c.f11556a;
        if (taskQueue.f11621b == null) {
            if (!taskQueue.f11622c.isEmpty()) {
                List<C4409b> addIfAbsent = this.f11633h;
                Intrinsics.checkParameterIsNotNull(addIfAbsent, "$this$addIfAbsent");
                if (!addIfAbsent.contains(taskQueue)) {
                    addIfAbsent.add(taskQueue);
                }
            } else {
                this.f11633h.remove(taskQueue);
            }
        }
        if (this.f11630e) {
            this.f11635j.mo5079a(this);
        } else {
            this.f11635j.execute(this.f11634i);
        }
    }

    @NotNull
    /* renamed from: f */
    public final C4409b m5078f() {
        int i2;
        synchronized (this) {
            i2 = this.f11629d;
            this.f11629d = i2 + 1;
        }
        StringBuilder sb = new StringBuilder();
        sb.append('Q');
        sb.append(i2);
        return new C4409b(this, sb.toString());
    }
}
