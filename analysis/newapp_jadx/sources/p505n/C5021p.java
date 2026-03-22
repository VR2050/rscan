package p505n;

import kotlin.Result;
import kotlin.ResultKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.InterfaceC3066i;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: n.p */
/* loaded from: classes3.dex */
public final class C5021p<T> implements InterfaceC5011f<T> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3066i f12838a;

    public C5021p(InterfaceC3066i interfaceC3066i) {
        this.f12838a = interfaceC3066i;
    }

    @Override // p505n.InterfaceC5011f
    /* renamed from: a */
    public void mo275a(@NotNull InterfaceC4983d<T> call, @NotNull Throwable t) {
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(t, "t");
        InterfaceC3066i interfaceC3066i = this.f12838a;
        Result.Companion companion = Result.INSTANCE;
        interfaceC3066i.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(t)));
    }

    @Override // p505n.InterfaceC5011f
    /* renamed from: b */
    public void mo276b(@NotNull InterfaceC4983d<T> call, @NotNull C5030y<T> response) {
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(response, "response");
        InterfaceC3066i interfaceC3066i = this.f12838a;
        Result.Companion companion = Result.INSTANCE;
        interfaceC3066i.resumeWith(Result.m6055constructorimpl(response));
    }
}
