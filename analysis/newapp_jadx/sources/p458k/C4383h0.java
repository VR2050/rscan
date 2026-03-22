package p458k;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p472io.CloseableKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4764z;

/* renamed from: k.h0 */
/* loaded from: classes3.dex */
public final class C4383h0 extends AbstractC4387j0 {

    /* renamed from: b */
    public final /* synthetic */ File f11454b;

    /* renamed from: c */
    public final /* synthetic */ C4371b0 f11455c;

    public C4383h0(File file, C4371b0 c4371b0) {
        this.f11454b = file;
        this.f11455c = c4371b0;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: a */
    public long mo4920a() {
        return this.f11454b.length();
    }

    @Override // p458k.AbstractC4387j0
    @Nullable
    /* renamed from: b */
    public C4371b0 mo4921b() {
        return this.f11455c;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: d */
    public void mo4922d(@NotNull InterfaceC4745g sink) {
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        InterfaceC4764z m2394G1 = C2354n.m2394G1(this.f11454b);
        try {
            sink.mo5396y(m2394G1);
            CloseableKt.closeFinally(m2394G1, null);
        } finally {
        }
    }
}
