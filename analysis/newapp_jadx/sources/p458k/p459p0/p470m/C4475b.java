package p458k.p459p0.p470m;

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: k.p0.m.b */
/* loaded from: classes3.dex */
public final class C4475b implements InterfaceC4478e {

    /* renamed from: a */
    public final Map<X500Principal, Set<X509Certificate>> f12009a;

    public C4475b(@NotNull X509Certificate... caCerts) {
        Intrinsics.checkParameterIsNotNull(caCerts, "caCerts");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (X509Certificate x509Certificate : caCerts) {
            X500Principal subjectX500Principal = x509Certificate.getSubjectX500Principal();
            Intrinsics.checkExpressionValueIsNotNull(subjectX500Principal, "caCert.subjectX500Principal");
            Object obj = linkedHashMap.get(subjectX500Principal);
            if (obj == null) {
                obj = new LinkedHashSet();
                linkedHashMap.put(subjectX500Principal, obj);
            }
            ((Set) obj).add(x509Certificate);
        }
        this.f12009a = linkedHashMap;
    }

    @Override // p458k.p459p0.p470m.InterfaceC4478e
    @Nullable
    /* renamed from: a */
    public X509Certificate mo5242a(@NotNull X509Certificate cert) {
        boolean z;
        Intrinsics.checkParameterIsNotNull(cert, "cert");
        Set<X509Certificate> set = this.f12009a.get(cert.getIssuerX500Principal());
        Object obj = null;
        if (set == null) {
            return null;
        }
        Iterator<T> it = set.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            try {
                cert.verify(((X509Certificate) next).getPublicKey());
                z = true;
            } catch (Exception unused) {
                z = false;
            }
            if (z) {
                obj = next;
                break;
            }
        }
        return (X509Certificate) obj;
    }

    public boolean equals(@Nullable Object obj) {
        return obj == this || ((obj instanceof C4475b) && Intrinsics.areEqual(((C4475b) obj).f12009a, this.f12009a));
    }

    public int hashCode() {
        return this.f12009a.hashCode();
    }
}
