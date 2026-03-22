package p458k.p459p0.p467k.p468h;

import android.net.http.X509TrustManagerExtensions;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.X509TrustManager;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.p459p0.p470m.AbstractC4476c;

/* renamed from: k.p0.k.h.a */
/* loaded from: classes3.dex */
public final class C4464a extends AbstractC4476c {

    /* renamed from: a */
    public final X509TrustManager f11989a;

    /* renamed from: b */
    public final X509TrustManagerExtensions f11990b;

    public C4464a(@NotNull X509TrustManager trustManager, @NotNull X509TrustManagerExtensions x509TrustManagerExtensions) {
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        Intrinsics.checkParameterIsNotNull(x509TrustManagerExtensions, "x509TrustManagerExtensions");
        this.f11989a = trustManager;
        this.f11990b = x509TrustManagerExtensions;
    }

    @Override // p458k.p459p0.p470m.AbstractC4476c
    @NotNull
    /* renamed from: a */
    public List<Certificate> mo5251a(@NotNull List<? extends Certificate> chain, @NotNull String hostname) {
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        Object[] array = chain.toArray(new X509Certificate[0]);
        if (array == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
        }
        try {
            List<X509Certificate> checkServerTrusted = this.f11990b.checkServerTrusted((X509Certificate[]) array, "RSA", hostname);
            Intrinsics.checkExpressionValueIsNotNull(checkServerTrusted, "x509TrustManagerExtensio…ficates, \"RSA\", hostname)");
            return checkServerTrusted;
        } catch (CertificateException e2) {
            SSLPeerUnverifiedException sSLPeerUnverifiedException = new SSLPeerUnverifiedException(e2.getMessage());
            sSLPeerUnverifiedException.initCause(e2);
            throw sSLPeerUnverifiedException;
        }
    }

    public boolean equals(@Nullable Object obj) {
        return (obj instanceof C4464a) && ((C4464a) obj).f11989a == this.f11989a;
    }

    public int hashCode() {
        return System.identityHashCode(this.f11989a);
    }
}
