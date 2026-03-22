package p458k.p459p0.p462f;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p458k.C4487x;

/* renamed from: k.p0.f.g */
/* loaded from: classes3.dex */
public final class C4417g extends Lambda implements Function0<List<? extends X509Certificate>> {

    /* renamed from: c */
    public final /* synthetic */ C4418h f11675c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4417g(C4418h c4418h) {
        super(0);
        this.f11675c = c4418h;
    }

    @Override // kotlin.jvm.functions.Function0
    public List<? extends X509Certificate> invoke() {
        C4487x c4487x = this.f11675c.f11678d;
        if (c4487x == null) {
            Intrinsics.throwNpe();
        }
        List<Certificate> m5273b = c4487x.m5273b();
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(m5273b, 10));
        for (Certificate certificate : m5273b) {
            if (certificate == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.security.cert.X509Certificate");
            }
            arrayList.add((X509Certificate) certificate);
        }
        return arrayList;
    }
}
