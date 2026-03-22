package p458k.p459p0.p470m;

import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: k.p0.m.a */
/* loaded from: classes3.dex */
public final class C4474a extends AbstractC4476c {

    /* renamed from: a */
    public final InterfaceC4478e f12008a;

    public C4474a(@NotNull InterfaceC4478e trustRootIndex) {
        Intrinsics.checkParameterIsNotNull(trustRootIndex, "trustRootIndex");
        this.f12008a = trustRootIndex;
    }

    @Override // p458k.p459p0.p470m.AbstractC4476c
    @NotNull
    /* renamed from: a */
    public List<Certificate> mo5251a(@NotNull List<? extends Certificate> chain, @NotNull String hostname) {
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        ArrayDeque arrayDeque = new ArrayDeque(chain);
        ArrayList arrayList = new ArrayList();
        Object removeFirst = arrayDeque.removeFirst();
        Intrinsics.checkExpressionValueIsNotNull(removeFirst, "queue.removeFirst()");
        arrayList.add(removeFirst);
        boolean z = false;
        for (int i2 = 0; i2 < 9; i2++) {
            Object obj = arrayList.get(arrayList.size() - 1);
            if (obj == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.security.cert.X509Certificate");
            }
            X509Certificate x509Certificate = (X509Certificate) obj;
            X509Certificate mo5242a = this.f12008a.mo5242a(x509Certificate);
            if (mo5242a == null) {
                Iterator it = arrayDeque.iterator();
                Intrinsics.checkExpressionValueIsNotNull(it, "queue.iterator()");
                while (it.hasNext()) {
                    Object next = it.next();
                    if (next == null) {
                        throw new TypeCastException("null cannot be cast to non-null type java.security.cert.X509Certificate");
                    }
                    X509Certificate x509Certificate2 = (X509Certificate) next;
                    if (m5257b(x509Certificate, x509Certificate2)) {
                        it.remove();
                        arrayList.add(x509Certificate2);
                    }
                }
                if (z) {
                    return arrayList;
                }
                throw new SSLPeerUnverifiedException("Failed to find a trusted cert that signed " + x509Certificate);
            }
            if (arrayList.size() > 1 || (!Intrinsics.areEqual(x509Certificate, mo5242a))) {
                arrayList.add(mo5242a);
            }
            if (m5257b(mo5242a, mo5242a)) {
                return arrayList;
            }
            z = true;
        }
        throw new SSLPeerUnverifiedException("Certificate chain too long: " + arrayList);
    }

    /* renamed from: b */
    public final boolean m5257b(X509Certificate x509Certificate, X509Certificate x509Certificate2) {
        if (!Intrinsics.areEqual(x509Certificate.getIssuerDN(), x509Certificate2.getSubjectDN())) {
            return false;
        }
        try {
            x509Certificate.verify(x509Certificate2.getPublicKey());
            return true;
        } catch (GeneralSecurityException unused) {
            return false;
        }
    }

    public boolean equals(@Nullable Object obj) {
        if (obj == this) {
            return true;
        }
        return (obj instanceof C4474a) && Intrinsics.areEqual(((C4474a) obj).f12008a, this.f12008a);
    }

    public int hashCode() {
        return this.f12008a.hashCode();
    }
}
