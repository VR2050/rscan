package p005b.p303q.p304a.p305a.p306a.p307a;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.InterfaceC3096s;
import p505n.C5015j;
import p505n.C5030y;
import p505n.InterfaceC4983d;
import p505n.InterfaceC5011f;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: b.q.a.a.a.a.b */
/* loaded from: classes2.dex */
public final class C2719b<T> implements InterfaceC5011f<T> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3096s f7391a;

    public C2719b(InterfaceC3096s interfaceC3096s) {
        this.f7391a = interfaceC3096s;
    }

    @Override // p505n.InterfaceC5011f
    /* renamed from: a */
    public void mo275a(@NotNull InterfaceC4983d<T> call, @NotNull Throwable t) {
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(t, "t");
        this.f7391a.mo3637D(t);
    }

    @Override // p505n.InterfaceC5011f
    /* renamed from: b */
    public void mo276b(@NotNull InterfaceC4983d<T> call, @NotNull C5030y<T> response) {
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(response, "response");
        if (!response.m5685a()) {
            this.f7391a.mo3637D(new C5015j(response));
            return;
        }
        InterfaceC3096s interfaceC3096s = this.f7391a;
        T t = response.f12958b;
        if (t == null) {
            Intrinsics.throwNpe();
        }
        interfaceC3096s.mo3638E(t);
    }
}
