package p379c.p380a.p382a2;

import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3072k;
import p379c.p380a.InterfaceC3066i;
import p379c.p380a.p381a.C2961j;
import p379c.p380a.p381a.C2970s;

/* renamed from: c.a.a2.v */
/* loaded from: classes2.dex */
public class C2999v<E> extends AbstractC2997t {

    /* renamed from: g */
    public final E f8185g;

    /* renamed from: h */
    @JvmField
    @NotNull
    public final InterfaceC3066i<Unit> f8186h;

    /* JADX WARN: Multi-variable type inference failed */
    public C2999v(E e2, @NotNull InterfaceC3066i<? super Unit> interfaceC3066i) {
        this.f8185g = e2;
        this.f8186h = interfaceC3066i;
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    /* renamed from: r */
    public void mo3487r() {
        this.f8186h.mo3567r(C3072k.f8424a);
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    /* renamed from: s */
    public E mo3488s() {
        return this.f8185g;
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    /* renamed from: t */
    public void mo3489t(@NotNull C2985h<?> c2985h) {
        InterfaceC3066i<Unit> interfaceC3066i = this.f8186h;
        Throwable m3494x = c2985h.m3494x();
        Result.Companion companion = Result.INSTANCE;
        interfaceC3066i.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(m3494x)));
    }

    @Override // p379c.p380a.p381a.C2961j
    @NotNull
    public String toString() {
        return getClass().getSimpleName() + '@' + C2354n.m2495m0(this) + '(' + this.f8185g + ')';
    }

    @Override // p379c.p380a.p382a2.AbstractC2997t
    @Nullable
    /* renamed from: u */
    public C2970s mo3490u(@Nullable C2961j.b bVar) {
        if (this.f8186h.mo3561a(Unit.INSTANCE, null) != null) {
            return C3072k.f8424a;
        }
        return null;
    }
}
