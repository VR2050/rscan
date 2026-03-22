package p458k.p459p0.p461e;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: k.p0.e.a */
/* loaded from: classes3.dex */
public abstract class AbstractC4408a {

    /* renamed from: a */
    @Nullable
    public C4409b f11616a;

    /* renamed from: b */
    public long f11617b;

    /* renamed from: c */
    @NotNull
    public final String f11618c;

    /* renamed from: d */
    public final boolean f11619d;

    public AbstractC4408a(@NotNull String name, boolean z) {
        Intrinsics.checkParameterIsNotNull(name, "name");
        this.f11618c = name;
        this.f11619d = z;
        this.f11617b = -1L;
    }

    /* renamed from: a */
    public abstract long mo5066a();

    @NotNull
    public String toString() {
        return this.f11618c;
    }
}
