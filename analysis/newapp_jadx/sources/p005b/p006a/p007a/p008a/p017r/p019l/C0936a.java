package p005b.p006a.p007a.p008a.p017r.p019l;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.a.a.a.r.l.a */
/* loaded from: classes2.dex */
public class C0936a extends Exception {

    /* renamed from: c */
    @Nullable
    public final Integer f465c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0936a(@NotNull String errorMsg, @Nullable Integer num) {
        super(errorMsg);
        Intrinsics.checkNotNullParameter(errorMsg, "errorMsg");
        this.f465c = num;
    }
}
