package p474l;

import java.io.InterruptedIOException;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: l.a0 */
/* loaded from: classes3.dex */
public class C4737a0 {

    /* renamed from: a */
    @JvmField
    @NotNull
    public static final C4737a0 f12115a = new a();

    /* renamed from: b */
    public boolean f12116b;

    /* renamed from: c */
    public long f12117c;

    /* renamed from: d */
    public long f12118d;

    /* renamed from: l.a0$a */
    public static final class a extends C4737a0 {
        @Override // p474l.C4737a0
        @NotNull
        /* renamed from: d */
        public C4737a0 mo5340d(long j2) {
            return this;
        }

        @Override // p474l.C4737a0
        /* renamed from: f */
        public void mo5342f() {
        }

        @Override // p474l.C4737a0
        @NotNull
        /* renamed from: g */
        public C4737a0 mo5343g(long j2, @NotNull TimeUnit unit) {
            Intrinsics.checkNotNullParameter(unit, "unit");
            return this;
        }
    }

    @NotNull
    /* renamed from: a */
    public C4737a0 mo5337a() {
        this.f12116b = false;
        return this;
    }

    @NotNull
    /* renamed from: b */
    public C4737a0 mo5338b() {
        this.f12118d = 0L;
        return this;
    }

    /* renamed from: c */
    public long mo5339c() {
        if (this.f12116b) {
            return this.f12117c;
        }
        throw new IllegalStateException("No deadline".toString());
    }

    @NotNull
    /* renamed from: d */
    public C4737a0 mo5340d(long j2) {
        this.f12116b = true;
        this.f12117c = j2;
        return this;
    }

    /* renamed from: e */
    public boolean mo5341e() {
        return this.f12116b;
    }

    /* renamed from: f */
    public void mo5342f() {
        if (Thread.interrupted()) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
        }
        if (this.f12116b && this.f12117c - System.nanoTime() <= 0) {
            throw new InterruptedIOException("deadline reached");
        }
    }

    @NotNull
    /* renamed from: g */
    public C4737a0 mo5343g(long j2, @NotNull TimeUnit unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("timeout < 0: ", j2).toString());
        }
        this.f12118d = unit.toNanos(j2);
        return this;
    }
}
