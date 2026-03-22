package p474l;

import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.l */
/* loaded from: classes3.dex */
public class C4750l extends C4737a0 {

    /* renamed from: e */
    @NotNull
    public C4737a0 f12142e;

    public C4750l(@NotNull C4737a0 delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.f12142e = delegate;
    }

    @Override // p474l.C4737a0
    @NotNull
    /* renamed from: a */
    public C4737a0 mo5337a() {
        return this.f12142e.mo5337a();
    }

    @Override // p474l.C4737a0
    @NotNull
    /* renamed from: b */
    public C4737a0 mo5338b() {
        return this.f12142e.mo5338b();
    }

    @Override // p474l.C4737a0
    /* renamed from: c */
    public long mo5339c() {
        return this.f12142e.mo5339c();
    }

    @Override // p474l.C4737a0
    @NotNull
    /* renamed from: d */
    public C4737a0 mo5340d(long j2) {
        return this.f12142e.mo5340d(j2);
    }

    @Override // p474l.C4737a0
    /* renamed from: e */
    public boolean mo5341e() {
        return this.f12142e.mo5341e();
    }

    @Override // p474l.C4737a0
    /* renamed from: f */
    public void mo5342f() {
        this.f12142e.mo5342f();
    }

    @Override // p474l.C4737a0
    @NotNull
    /* renamed from: g */
    public C4737a0 mo5343g(long j2, @NotNull TimeUnit unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        return this.f12142e.mo5343g(j2, unit);
    }
}
