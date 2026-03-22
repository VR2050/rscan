package p458k;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p474l.InterfaceC4745g;

/* renamed from: k.i0 */
/* loaded from: classes3.dex */
public final class C4385i0 extends AbstractC4387j0 {

    /* renamed from: b */
    public final /* synthetic */ byte[] f11459b;

    /* renamed from: c */
    public final /* synthetic */ C4371b0 f11460c;

    /* renamed from: d */
    public final /* synthetic */ int f11461d;

    /* renamed from: e */
    public final /* synthetic */ int f11462e;

    public C4385i0(byte[] bArr, C4371b0 c4371b0, int i2, int i3) {
        this.f11459b = bArr;
        this.f11460c = c4371b0;
        this.f11461d = i2;
        this.f11462e = i3;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: a */
    public long mo4920a() {
        return this.f11461d;
    }

    @Override // p458k.AbstractC4387j0
    @Nullable
    /* renamed from: b */
    public C4371b0 mo4921b() {
        return this.f11460c;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: d */
    public void mo4922d(@NotNull InterfaceC4745g sink) {
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        sink.mo5373a(this.f11459b, this.f11462e, this.f11461d);
    }
}
