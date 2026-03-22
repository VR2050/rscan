package p379c.p380a.p382a2;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3066i;
import p379c.p380a.p381a.C2975x;

/* renamed from: c.a.a2.w */
/* loaded from: classes2.dex */
public final class C3000w<E> extends C2999v<E> {

    /* renamed from: i */
    @JvmField
    @NotNull
    public final Function1<E, Unit> f8187i;

    /* JADX WARN: Multi-variable type inference failed */
    public C3000w(E e2, @NotNull InterfaceC3066i<? super Unit> interfaceC3066i, @NotNull Function1<? super E, Unit> function1) {
        super(e2, interfaceC3066i);
        this.f8187i = function1;
    }

    @Override // p379c.p380a.p381a.C2961j
    /* renamed from: o */
    public boolean mo3424o() {
        if (!super.mo3424o()) {
            return false;
        }
        mo3502v();
        return true;
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    /* renamed from: v */
    public void mo3502v() {
        Function1<E, Unit> function1 = this.f8187i;
        E e2 = this.f8185g;
        CoroutineContext coroutineContext = this.f8186h.get$context();
        C2975x m2503p = C2354n.m2503p(function1, e2, null);
        if (m2503p != null) {
            C2354n.m2516t0(coroutineContext, m2503p);
        }
    }
}
