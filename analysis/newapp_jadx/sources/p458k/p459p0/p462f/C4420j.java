package p458k.p459p0.p462f;

import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.C4395n0;

/* renamed from: k.p0.f.j */
/* loaded from: classes3.dex */
public final class C4420j {

    /* renamed from: a */
    public final Set<C4395n0> f11699a = new LinkedHashSet();

    /* renamed from: a */
    public final synchronized void m5112a(@NotNull C4395n0 route) {
        Intrinsics.checkParameterIsNotNull(route, "route");
        this.f11699a.remove(route);
    }
}
