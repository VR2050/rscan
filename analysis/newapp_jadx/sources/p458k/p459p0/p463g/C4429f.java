package p458k.p459p0.p463g;

import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: k.p0.g.f */
/* loaded from: classes3.dex */
public final class C4429f {
    @JvmStatic
    /* renamed from: a */
    public static final boolean m5137a(@NotNull String method) {
        Intrinsics.checkParameterIsNotNull(method, "method");
        return (Intrinsics.areEqual(method, "GET") || Intrinsics.areEqual(method, "HEAD")) ? false : true;
    }
}
