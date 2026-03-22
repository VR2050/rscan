package p379c.p380a.p382a2;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.p381a.C2959h;
import p379c.p380a.p381a.C2961j;
import p379c.p380a.p381a.C2970s;
import p379c.p380a.p382a2.AbstractC2980c;

/* renamed from: c.a.a2.l */
/* loaded from: classes2.dex */
public class C2989l<E> extends AbstractC2978a<E> {
    public C2989l(@Nullable Function1<? super E, Unit> function1) {
        super(function1);
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    /* renamed from: l */
    public final boolean mo3481l() {
        return false;
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    /* renamed from: o */
    public final boolean mo3483o() {
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p379c.p380a.p382a2.AbstractC2980c
    @NotNull
    /* renamed from: q */
    public Object mo3485q(E e2) {
        InterfaceC2995r interfaceC2995r;
        do {
            Object mo3485q = super.mo3485q(e2);
            C2970s c2970s = C2979b.f8159b;
            if (mo3485q == c2970s) {
                return c2970s;
            }
            if (mo3485q != C2979b.f8160c) {
                if (mo3485q instanceof C2985h) {
                    return mo3485q;
                }
                throw new IllegalStateException(C1499a.m636v("Invalid offerInternal result ", mo3485q).toString());
            }
            C2959h c2959h = this.f8165e;
            AbstractC2980c.a aVar = new AbstractC2980c.a(e2);
            while (true) {
                C2961j m3430l = c2959h.m3430l();
                if (m3430l instanceof InterfaceC2995r) {
                    interfaceC2995r = (InterfaceC2995r) m3430l;
                    break;
                }
                if (m3430l.m3425g(aVar, c2959h)) {
                    interfaceC2995r = null;
                    break;
                }
            }
            if (interfaceC2995r == null) {
                return C2979b.f8159b;
            }
        } while (!(interfaceC2995r instanceof C2985h));
        return interfaceC2995r;
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: u */
    public final boolean mo3463u() {
        return true;
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: v */
    public final boolean mo3464v() {
        return true;
    }
}
