package p458k.p459p0.p462f;

import java.security.cert.Certificate;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p458k.C4368a;
import p458k.C4382h;
import p458k.C4487x;
import p458k.p459p0.p470m.AbstractC4476c;

/* renamed from: k.p0.f.f */
/* loaded from: classes3.dex */
public final class C4416f extends Lambda implements Function0<List<? extends Certificate>> {

    /* renamed from: c */
    public final /* synthetic */ C4382h f11672c;

    /* renamed from: e */
    public final /* synthetic */ C4487x f11673e;

    /* renamed from: f */
    public final /* synthetic */ C4368a f11674f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4416f(C4382h c4382h, C4487x c4487x, C4368a c4368a) {
        super(0);
        this.f11672c = c4382h;
        this.f11673e = c4487x;
        this.f11674f = c4368a;
    }

    @Override // kotlin.jvm.functions.Function0
    public List<? extends Certificate> invoke() {
        AbstractC4476c abstractC4476c = this.f11672c.f11453d;
        if (abstractC4476c == null) {
            Intrinsics.throwNpe();
        }
        return abstractC4476c.mo5251a(this.f11673e.m5273b(), this.f11674f.f11296a.f12049g);
    }
}
