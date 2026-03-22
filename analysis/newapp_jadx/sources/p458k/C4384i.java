package p458k;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;
import p458k.p459p0.p470m.AbstractC4476c;

/* renamed from: k.i */
/* loaded from: classes3.dex */
public final class C4384i extends Lambda implements Function0<List<? extends X509Certificate>> {

    /* renamed from: c */
    public final /* synthetic */ C4382h f11456c;

    /* renamed from: e */
    public final /* synthetic */ List f11457e;

    /* renamed from: f */
    public final /* synthetic */ String f11458f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4384i(C4382h c4382h, List list, String str) {
        super(0);
        this.f11456c = c4382h;
        this.f11457e = list;
        this.f11458f = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public List<? extends X509Certificate> invoke() {
        List<Certificate> list;
        AbstractC4476c abstractC4476c = this.f11456c.f11453d;
        if (abstractC4476c == null || (list = abstractC4476c.mo5251a(this.f11457e, this.f11458f)) == null) {
            list = this.f11457e;
        }
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(list, 10));
        for (Certificate certificate : list) {
            if (certificate == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.security.cert.X509Certificate");
            }
            arrayList.add((X509Certificate) certificate);
        }
        return arrayList;
    }
}
