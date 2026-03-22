package p379c.p380a;

import kotlin.Unit;
import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.o */
/* loaded from: classes2.dex */
public final class C3084o extends AbstractC3059f1<C3068i1> implements InterfaceC3081n {

    /* renamed from: h */
    @JvmField
    @NotNull
    public final InterfaceC3087p f8434h;

    public C3084o(@NotNull C3068i1 c3068i1, @NotNull InterfaceC3087p interfaceC3087p) {
        super(c3068i1);
        this.f8434h = interfaceC3087p;
    }

    @Override // p379c.p380a.InterfaceC3081n
    /* renamed from: c */
    public boolean mo3622c(@NotNull Throwable th) {
        return ((C3068i1) this.f8403g).mo3570A(th);
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(Throwable th) {
        mo3514r(th);
        return Unit.INSTANCE;
    }

    @Override // p379c.p380a.AbstractC3114y
    /* renamed from: r */
    public void mo3514r(@Nullable Throwable th) {
        this.f8434h.mo3590t((InterfaceC3089p1) this.f8403g);
    }

    @Override // p379c.p380a.p381a.C2961j
    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("ChildHandle[");
        m586H.append(this.f8434h);
        m586H.append(']');
        return m586H.toString();
    }
}
