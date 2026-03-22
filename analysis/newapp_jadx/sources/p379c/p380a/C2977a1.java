package p379c.p380a;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: c.a.a1 */
/* loaded from: classes2.dex */
public final class C2977a1 extends AbstractC3060g {

    /* renamed from: c */
    public final Function1<Throwable, Unit> f8142c;

    /* JADX WARN: Multi-variable type inference failed */
    public C2977a1(@NotNull Function1<? super Throwable, Unit> function1) {
        this.f8142c = function1;
    }

    @Override // p379c.p380a.AbstractC3063h
    /* renamed from: a */
    public void mo3456a(@Nullable Throwable th) {
        this.f8142c.invoke(th);
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        this.f8142c.invoke(th);
        return Unit.INSTANCE;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("InvokeOnCancel[");
        m586H.append(C2354n.m2489k0(this.f8142c));
        m586H.append('@');
        m586H.append(C2354n.m2495m0(this));
        m586H.append(']');
        return m586H.toString();
    }
}
