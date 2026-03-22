package p379c.p380a;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.p0 */
/* loaded from: classes2.dex */
public final class C3088p0 implements InterfaceC3115y0 {

    /* renamed from: c */
    public final boolean f8436c;

    public C3088p0(boolean z) {
        this.f8436c = z;
    }

    @Override // p379c.p380a.InterfaceC3115y0
    /* renamed from: b */
    public boolean mo3559b() {
        return this.f8436c;
    }

    @Override // p379c.p380a.InterfaceC3115y0
    @Nullable
    /* renamed from: d */
    public C3080m1 mo3560d() {
        return null;
    }

    @NotNull
    public String toString() {
        return C1499a.m581C(C1499a.m586H("Empty{"), this.f8436c ? "Active" : "New", '}');
    }
}
