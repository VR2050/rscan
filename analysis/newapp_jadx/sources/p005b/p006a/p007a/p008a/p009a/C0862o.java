package p005b.p006a.p007a.p008a.p009a;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p327w.p330b.p336c.C2853d;
import p005b.p327w.p330b.p337d.C2859c;
import p458k.AbstractC4393m0;
import p458k.C4389k0;
import p458k.InterfaceC4378f;
import p458k.InterfaceC4380g;

/* renamed from: b.a.a.a.a.o */
/* loaded from: classes2.dex */
public final class C0862o implements InterfaceC4380g {

    /* renamed from: a */
    public final /* synthetic */ C2859c.c f295a;

    public C0862o(C2859c.c cVar) {
        this.f295a = cVar;
    }

    @Override // p458k.InterfaceC4380g
    /* renamed from: a */
    public void mo195a(@NotNull InterfaceC4378f call, @NotNull C4389k0 response) {
        String str;
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(response, "response");
        C2853d c2853d = C2853d.f7770a;
        AbstractC4393m0 abstractC4393m0 = response.f11491k;
        Intrinsics.checkNotNull(abstractC4393m0);
        byte[] m3299a = c2853d.m3299a(abstractC4393m0.m5007b(), "525202f9149e061d");
        if (m3299a == null) {
            str = null;
        } else {
            Charset UTF_8 = StandardCharsets.UTF_8;
            Intrinsics.checkNotNullExpressionValue(UTF_8, "UTF_8");
            str = new String(m3299a, UTF_8);
        }
        this.f295a.onDownloadSuccessData(str);
    }

    @Override // p458k.InterfaceC4380g
    /* renamed from: b */
    public void mo196b(@NotNull InterfaceC4378f call, @NotNull IOException e2) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(e2, "e");
        this.f295a.onDownloadFailed();
    }
}
