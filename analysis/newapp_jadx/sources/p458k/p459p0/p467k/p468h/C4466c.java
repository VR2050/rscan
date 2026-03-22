package p458k.p459p0.p467k.p468h;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.X509TrustManager;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.p459p0.p470m.AbstractC4476c;

/* renamed from: k.p0.k.h.c */
/* loaded from: classes3.dex */
public final class C4466c extends AbstractC4476c {

    /* renamed from: a */
    public final X509TrustManager f11992a;

    /* renamed from: b */
    public final Object f11993b;

    /* renamed from: c */
    public final Method f11994c;

    public C4466c(@NotNull X509TrustManager trustManager, @NotNull Object x509TrustManagerExtensions, @NotNull Method checkServerTrusted) {
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        Intrinsics.checkParameterIsNotNull(x509TrustManagerExtensions, "x509TrustManagerExtensions");
        Intrinsics.checkParameterIsNotNull(checkServerTrusted, "checkServerTrusted");
        this.f11992a = trustManager;
        this.f11993b = x509TrustManagerExtensions;
        this.f11994c = checkServerTrusted;
    }

    @Override // p458k.p459p0.p470m.AbstractC4476c
    @NotNull
    /* renamed from: a */
    public List<Certificate> mo5251a(@NotNull List<? extends Certificate> chain, @NotNull String hostname) {
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        try {
            Object[] array = chain.toArray(new X509Certificate[0]);
            if (array == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            Object invoke = this.f11994c.invoke(this.f11993b, (X509Certificate[]) array, "RSA", hostname);
            if (invoke != null) {
                return (List) invoke;
            }
            throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.List<java.security.cert.Certificate>");
        } catch (IllegalAccessException e2) {
            throw new AssertionError(e2);
        } catch (InvocationTargetException e3) {
            SSLPeerUnverifiedException sSLPeerUnverifiedException = new SSLPeerUnverifiedException(e3.getMessage());
            sSLPeerUnverifiedException.initCause(e3);
            throw sSLPeerUnverifiedException;
        }
    }

    public boolean equals(@Nullable Object obj) {
        return (obj instanceof C4466c) && ((C4466c) obj).f11992a == this.f11992a;
    }

    public int hashCode() {
        return System.identityHashCode(this.f11992a);
    }
}
