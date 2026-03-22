package p458k.p459p0.p465i;

import java.io.IOException;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: k.p0.i.u */
/* loaded from: classes3.dex */
public final class C4455u extends IOException {

    /* renamed from: c */
    @JvmField
    @NotNull
    public final EnumC4436b f11957c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4455u(@NotNull EnumC4436b errorCode) {
        super("stream was reset: " + errorCode);
        Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
        this.f11957c = errorCode;
    }
}
