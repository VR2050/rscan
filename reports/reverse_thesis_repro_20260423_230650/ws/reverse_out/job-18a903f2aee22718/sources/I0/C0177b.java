package I0;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: I0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0177b implements InterfaceC0191p {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final a f1191f = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f1192a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Executor f1193b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Executor f1194c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Executor f1195d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final ScheduledExecutorService f1196e;

    /* JADX INFO: renamed from: I0.b$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public C0177b(int i3) {
        ExecutorService executorServiceNewFixedThreadPool = Executors.newFixedThreadPool(2, new B(10, "FrescoIoBoundExecutor", true));
        t2.j.e(executorServiceNewFixedThreadPool, "newFixedThreadPool(...)");
        this.f1192a = executorServiceNewFixedThreadPool;
        ExecutorService executorServiceNewFixedThreadPool2 = Executors.newFixedThreadPool(i3, new B(10, "FrescoDecodeExecutor", true));
        t2.j.e(executorServiceNewFixedThreadPool2, "newFixedThreadPool(...)");
        this.f1193b = executorServiceNewFixedThreadPool2;
        ExecutorService executorServiceNewFixedThreadPool3 = Executors.newFixedThreadPool(i3, new B(10, "FrescoBackgroundExecutor", true));
        t2.j.e(executorServiceNewFixedThreadPool3, "newFixedThreadPool(...)");
        this.f1194c = executorServiceNewFixedThreadPool3;
        ExecutorService executorServiceNewFixedThreadPool4 = Executors.newFixedThreadPool(1, new B(10, "FrescoLightWeightBackgroundExecutor", true));
        t2.j.e(executorServiceNewFixedThreadPool4, "newFixedThreadPool(...)");
        this.f1195d = executorServiceNewFixedThreadPool4;
        ScheduledExecutorService scheduledExecutorServiceNewScheduledThreadPool = Executors.newScheduledThreadPool(i3, new B(10, "FrescoBackgroundExecutor", true));
        t2.j.e(scheduledExecutorServiceNewScheduledThreadPool, "newScheduledThreadPool(...)");
        this.f1196e = scheduledExecutorServiceNewScheduledThreadPool;
    }

    @Override // I0.InterfaceC0191p
    public Executor a() {
        return this.f1193b;
    }

    @Override // I0.InterfaceC0191p
    public Executor b() {
        return this.f1195d;
    }

    @Override // I0.InterfaceC0191p
    public Executor c() {
        return this.f1192a;
    }

    @Override // I0.InterfaceC0191p
    public Executor d() {
        return this.f1192a;
    }

    @Override // I0.InterfaceC0191p
    public Executor e() {
        return this.f1194c;
    }

    @Override // I0.InterfaceC0191p
    public Executor f() {
        return this.f1192a;
    }

    @Override // I0.InterfaceC0191p
    public ScheduledExecutorService g() {
        return this.f1196e;
    }
}
