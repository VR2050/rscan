package p458k;

import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.p459p0.p461e.C4410c;
import p458k.p459p0.p462f.C4419i;

/* renamed from: k.l */
/* loaded from: classes3.dex */
public final class C4390l {

    /* renamed from: a */
    @NotNull
    public final C4419i f11511a;

    public C4390l() {
        TimeUnit timeUnit = TimeUnit.MINUTES;
        Intrinsics.checkParameterIsNotNull(timeUnit, "timeUnit");
        C4419i delegate = new C4419i(C4410c.f11626a, 5, 5L, timeUnit);
        Intrinsics.checkParameterIsNotNull(delegate, "delegate");
        this.f11511a = delegate;
    }
}
