package p379c.p380a;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: c.a.c1 */
/* loaded from: classes2.dex */
public final class C3037c1 extends AbstractC3065h1<InterfaceC3053d1> {

    /* renamed from: h */
    public final Function1<Throwable, Unit> f8344h;

    /* JADX WARN: Multi-variable type inference failed */
    public C3037c1(@NotNull InterfaceC3053d1 interfaceC3053d1, @NotNull Function1<? super Throwable, Unit> function1) {
        super(interfaceC3053d1);
        this.f8344h = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        this.f8344h.invoke(th);
        return Unit.INSTANCE;
    }

    @Override // p379c.p380a.AbstractC3114y
    /* renamed from: r */
    public void mo3514r(@Nullable Throwable th) {
        this.f8344h.invoke(th);
    }

    @Override // p379c.p380a.p381a.C2961j
    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("InvokeOnCompletion[");
        m586H.append(C3037c1.class.getSimpleName());
        m586H.append('@');
        m586H.append(C2354n.m2495m0(this));
        m586H.append(']');
        return m586H.toString();
    }
}
