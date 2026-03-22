package p379c.p380a;

import kotlin.Unit;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.o0 */
/* loaded from: classes2.dex */
public final class C3085o0 extends AbstractC3060g {

    /* renamed from: c */
    public final InterfaceC3082n0 f8435c;

    public C3085o0(@NotNull InterfaceC3082n0 interfaceC3082n0) {
        this.f8435c = interfaceC3082n0;
    }

    @Override // p379c.p380a.AbstractC3063h
    /* renamed from: a */
    public void mo3456a(@Nullable Throwable th) {
        this.f8435c.dispose();
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(Throwable th) {
        this.f8435c.dispose();
        return Unit.INSTANCE;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("DisposeOnCancel[");
        m586H.append(this.f8435c);
        m586H.append(']');
        return m586H.toString();
    }
}
