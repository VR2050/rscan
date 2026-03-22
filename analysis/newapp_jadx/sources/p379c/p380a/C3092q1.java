package p379c.p380a;

import kotlin.Unit;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.p381a.C2961j;

/* renamed from: c.a.q1 */
/* loaded from: classes2.dex */
public final class C3092q1 extends AbstractC3051d {

    /* renamed from: c */
    public final C2961j f8444c;

    public C3092q1(@NotNull C2961j c2961j) {
        this.f8444c = c2961j;
    }

    @Override // p379c.p380a.AbstractC3063h
    /* renamed from: a */
    public void mo3456a(@Nullable Throwable th) {
        this.f8444c.mo3424o();
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        this.f8444c.mo3424o();
        return Unit.INSTANCE;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("RemoveOnCancel[");
        m586H.append(this.f8444c);
        m586H.append(']');
        return m586H.toString();
    }
}
