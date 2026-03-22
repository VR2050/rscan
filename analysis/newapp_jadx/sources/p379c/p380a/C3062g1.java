package p379c.p380a;

import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.g1 */
/* loaded from: classes2.dex */
public class C3062g1 extends C3068i1 implements InterfaceC3102u {

    /* renamed from: e */
    public final boolean f8401e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3062g1(@Nullable InterfaceC3053d1 interfaceC3053d1) {
        super(true);
        C3068i1 c3068i1;
        boolean z = true;
        m3578O(interfaceC3053d1);
        InterfaceC3081n interfaceC3081n = (InterfaceC3081n) this._parentHandle;
        C3084o c3084o = (C3084o) (interfaceC3081n instanceof C3084o ? interfaceC3081n : null);
        if (c3084o != null && (c3068i1 = (C3068i1) c3084o.f8403g) != null) {
            while (!c3068i1.mo3557H()) {
                InterfaceC3081n interfaceC3081n2 = (InterfaceC3081n) c3068i1._parentHandle;
                C3084o c3084o2 = (C3084o) (interfaceC3081n2 instanceof C3084o ? interfaceC3081n2 : null);
                if (c3084o2 != null && (c3068i1 = (C3068i1) c3084o2.f8403g) != null) {
                }
            }
            this.f8401e = z;
        }
        z = false;
        this.f8401e = z;
    }

    @Override // p379c.p380a.C3068i1
    /* renamed from: H */
    public boolean mo3557H() {
        return this.f8401e;
    }

    @Override // p379c.p380a.C3068i1
    /* renamed from: J */
    public boolean mo3558J() {
        return true;
    }
}
