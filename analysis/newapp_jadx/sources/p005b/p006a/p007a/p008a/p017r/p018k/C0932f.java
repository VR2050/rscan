package p005b.p006a.p007a.p008a.p017r.p018k;

import java.lang.reflect.Type;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.p383b2.C3016l;
import p379c.p380a.p383b2.InterfaceC3006b;
import p505n.InterfaceC4983d;
import p505n.InterfaceC4985e;

/* renamed from: b.a.a.a.r.k.f */
/* loaded from: classes2.dex */
public final class C0932f<T> implements InterfaceC4985e<T, InterfaceC3006b<? extends T>> {

    /* renamed from: a */
    @NotNull
    public final Type f457a;

    public C0932f(@NotNull Type responseType) {
        Intrinsics.checkNotNullParameter(responseType, "responseType");
        this.f457a = responseType;
    }

    @Override // p505n.InterfaceC4985e
    @NotNull
    /* renamed from: a */
    public Type mo277a() {
        return this.f457a;
    }

    @Override // p505n.InterfaceC4985e
    /* renamed from: b */
    public Object mo278b(InterfaceC4983d call) {
        Intrinsics.checkNotNullParameter(call, "call");
        return new C3016l(new C0931e(call, null));
    }
}
