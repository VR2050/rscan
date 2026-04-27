package F2;

import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private d f738a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private long f739b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f740c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f741d;

    public a(String str, boolean z3) {
        j.f(str, "name");
        this.f740c = str;
        this.f741d = z3;
        this.f739b = -1L;
    }

    public final boolean a() {
        return this.f741d;
    }

    public final String b() {
        return this.f740c;
    }

    public final long c() {
        return this.f739b;
    }

    public final d d() {
        return this.f738a;
    }

    public final void e(d dVar) {
        j.f(dVar, "queue");
        d dVar2 = this.f738a;
        if (dVar2 == dVar) {
            return;
        }
        if (!(dVar2 == null)) {
            throw new IllegalStateException("task is in multiple queues");
        }
        this.f738a = dVar;
    }

    public abstract long f();

    public final void g(long j3) {
        this.f739b = j3;
    }

    public String toString() {
        return this.f740c;
    }

    public /* synthetic */ a(String str, boolean z3, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, (i3 & 2) != 0 ? true : z3);
    }
}
