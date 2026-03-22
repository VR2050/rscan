package p458k.p459p0.p462f;

import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: k.p0.f.k */
/* loaded from: classes3.dex */
public final class C4421k extends RuntimeException {

    /* renamed from: c */
    @NotNull
    public IOException f11700c;

    /* renamed from: e */
    @NotNull
    public final IOException f11701e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4421k(@NotNull IOException firstConnectException) {
        super(firstConnectException);
        Intrinsics.checkParameterIsNotNull(firstConnectException, "firstConnectException");
        this.f11701e = firstConnectException;
        this.f11700c = firstConnectException;
    }
}
