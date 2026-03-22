package p458k.p459p0.p463g;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p474l.InterfaceC4746h;

/* renamed from: k.p0.g.h */
/* loaded from: classes3.dex */
public final class C4431h extends AbstractC4393m0 {

    /* renamed from: e */
    public final String f11744e;

    /* renamed from: f */
    public final long f11745f;

    /* renamed from: g */
    public final InterfaceC4746h f11746g;

    public C4431h(@Nullable String str, long j2, @NotNull InterfaceC4746h source) {
        Intrinsics.checkParameterIsNotNull(source, "source");
        this.f11744e = str;
        this.f11745f = j2;
        this.f11746g = source;
    }

    @Override // p458k.AbstractC4393m0
    /* renamed from: d */
    public long mo4925d() {
        return this.f11745f;
    }

    @Override // p458k.AbstractC4393m0
    @Nullable
    /* renamed from: e */
    public C4371b0 mo4926e() {
        String str = this.f11744e;
        if (str == null) {
            return null;
        }
        C4371b0.a aVar = C4371b0.f11309c;
        return C4371b0.a.m4946b(str);
    }

    @Override // p458k.AbstractC4393m0
    @NotNull
    /* renamed from: k */
    public InterfaceC4746h mo4927k() {
        return this.f11746g;
    }
}
