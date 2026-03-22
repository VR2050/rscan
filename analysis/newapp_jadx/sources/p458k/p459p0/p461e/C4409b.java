package p458k.p459p0.p461e;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.logging.Level;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.C4410c;

/* renamed from: k.p0.e.b */
/* loaded from: classes3.dex */
public final class C4409b {

    /* renamed from: a */
    public boolean f11620a;

    /* renamed from: b */
    @Nullable
    public AbstractC4408a f11621b;

    /* renamed from: c */
    @NotNull
    public final List<AbstractC4408a> f11622c;

    /* renamed from: d */
    public boolean f11623d;

    /* renamed from: e */
    @NotNull
    public final C4410c f11624e;

    /* renamed from: f */
    @NotNull
    public final String f11625f;

    public C4409b(@NotNull C4410c taskRunner, @NotNull String name) {
        Intrinsics.checkParameterIsNotNull(taskRunner, "taskRunner");
        Intrinsics.checkParameterIsNotNull(name, "name");
        this.f11624e = taskRunner;
        this.f11625f = name;
        this.f11622c = new ArrayList();
    }

    /* renamed from: d */
    public static /* synthetic */ void m5067d(C4409b c4409b, AbstractC4408a abstractC4408a, long j2, int i2) {
        if ((i2 & 2) != 0) {
            j2 = 0;
        }
        c4409b.m5070c(abstractC4408a, j2);
    }

    /* renamed from: a */
    public final void m5068a() {
        byte[] bArr = C4401c.f11556a;
        synchronized (this.f11624e) {
            if (m5069b()) {
                this.f11624e.m5077e(this);
            }
            Unit unit = Unit.INSTANCE;
        }
    }

    /* renamed from: b */
    public final boolean m5069b() {
        AbstractC4408a abstractC4408a = this.f11621b;
        if (abstractC4408a != null) {
            if (abstractC4408a == null) {
                Intrinsics.throwNpe();
            }
            if (abstractC4408a.f11619d) {
                this.f11623d = true;
            }
        }
        boolean z = false;
        for (int size = this.f11622c.size() - 1; size >= 0; size--) {
            if (this.f11622c.get(size).f11619d) {
                AbstractC4408a abstractC4408a2 = this.f11622c.get(size);
                C4410c.b bVar = C4410c.f11628c;
                if (C4410c.f11627b.isLoggable(Level.FINE)) {
                    C2354n.m2464d(abstractC4408a2, this, "canceled");
                }
                this.f11622c.remove(size);
                z = true;
            }
        }
        return z;
    }

    /* renamed from: c */
    public final void m5070c(@NotNull AbstractC4408a task, long j2) {
        Intrinsics.checkParameterIsNotNull(task, "task");
        synchronized (this.f11624e) {
            if (!this.f11620a) {
                if (m5071e(task, j2, false)) {
                    this.f11624e.m5077e(this);
                }
                Unit unit = Unit.INSTANCE;
            } else if (task.f11619d) {
                C4410c.b bVar = C4410c.f11628c;
                if (C4410c.f11627b.isLoggable(Level.FINE)) {
                    C2354n.m2464d(task, this, "schedule canceled (queue is shutdown)");
                }
            } else {
                C4410c.b bVar2 = C4410c.f11628c;
                if (C4410c.f11627b.isLoggable(Level.FINE)) {
                    C2354n.m2464d(task, this, "schedule failed (queue is shutdown)");
                }
                throw new RejectedExecutionException();
            }
        }
    }

    /* renamed from: e */
    public final boolean m5071e(@NotNull AbstractC4408a task, long j2, boolean z) {
        String sb;
        Intrinsics.checkParameterIsNotNull(task, "task");
        Objects.requireNonNull(task);
        Intrinsics.checkParameterIsNotNull(this, "queue");
        C4409b c4409b = task.f11616a;
        if (c4409b != this) {
            if (!(c4409b == null)) {
                throw new IllegalStateException("task is in multiple queues".toString());
            }
            task.f11616a = this;
        }
        long mo5081c = this.f11624e.f11635j.mo5081c();
        long j3 = mo5081c + j2;
        int indexOf = this.f11622c.indexOf(task);
        if (indexOf != -1) {
            if (task.f11617b <= j3) {
                C4410c.b bVar = C4410c.f11628c;
                if (C4410c.f11627b.isLoggable(Level.FINE)) {
                    C2354n.m2464d(task, this, "already scheduled");
                }
                return false;
            }
            this.f11622c.remove(indexOf);
        }
        task.f11617b = j3;
        C4410c.b bVar2 = C4410c.f11628c;
        if (C4410c.f11627b.isLoggable(Level.FINE)) {
            if (z) {
                StringBuilder m586H = C1499a.m586H("run again after ");
                m586H.append(C2354n.m2473f0(j3 - mo5081c));
                sb = m586H.toString();
            } else {
                StringBuilder m586H2 = C1499a.m586H("scheduled after ");
                m586H2.append(C2354n.m2473f0(j3 - mo5081c));
                sb = m586H2.toString();
            }
            C2354n.m2464d(task, this, sb);
        }
        Iterator<AbstractC4408a> it = this.f11622c.iterator();
        int i2 = 0;
        while (true) {
            if (!it.hasNext()) {
                i2 = -1;
                break;
            }
            if (it.next().f11617b - mo5081c > j2) {
                break;
            }
            i2++;
        }
        if (i2 == -1) {
            i2 = this.f11622c.size();
        }
        this.f11622c.add(i2, task);
        return i2 == 0;
    }

    /* renamed from: f */
    public final void m5072f() {
        byte[] bArr = C4401c.f11556a;
        synchronized (this.f11624e) {
            this.f11620a = true;
            if (m5069b()) {
                this.f11624e.m5077e(this);
            }
            Unit unit = Unit.INSTANCE;
        }
    }

    @NotNull
    public String toString() {
        return this.f11625f;
    }
}
