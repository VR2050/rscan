package p458k.p459p0.p467k;

import java.security.KeyStore;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.internal.Intrinsics;
import org.conscrypt.NativeCrypto;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.openjsse.javax.net.ssl.SSLParameters;
import org.openjsse.net.ssl.OpenJSSE;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.EnumC4377e0;

/* renamed from: k.p0.k.f */
/* loaded from: classes3.dex */
public final class C4462f extends C4463g {

    /* renamed from: d */
    public static final boolean f11983d;

    /* renamed from: e */
    public static final C4462f f11984e = null;

    /* renamed from: f */
    public final Provider f11985f = new OpenJSSE();

    static {
        boolean z;
        try {
            Class.forName("org.openjsse.net.ssl.OpenJSSE");
            z = true;
        } catch (ClassNotFoundException unused) {
            z = false;
        }
        f11983d = z;
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: e */
    public void mo5233e(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        if (!(sslSocket instanceof org.openjsse.javax.net.ssl.SSLSocket)) {
            Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
            Intrinsics.checkParameterIsNotNull(protocols, "protocols");
            return;
        }
        org.openjsse.javax.net.ssl.SSLSocket sSLSocket = (org.openjsse.javax.net.ssl.SSLSocket) sslSocket;
        SSLParameters sSLParameters = sSLSocket.getSSLParameters();
        if (sSLParameters instanceof SSLParameters) {
            Intrinsics.checkParameterIsNotNull(protocols, "protocols");
            ArrayList arrayList = new ArrayList();
            Iterator<T> it = protocols.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                Object next = it.next();
                if (((EnumC4377e0) next) != EnumC4377e0.HTTP_1_0) {
                    arrayList.add(next);
                }
            }
            ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(((EnumC4377e0) it2.next()).f11430l);
            }
            SSLParameters sSLParameters2 = sSLParameters;
            Object[] array = arrayList2.toArray(new String[0]);
            if (array == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            sSLParameters2.setApplicationProtocols((String[]) array);
            sSLSocket.setSSLParameters(sSLParameters);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    @Nullable
    /* renamed from: h */
    public String mo5234h(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        if (sslSocket instanceof org.openjsse.javax.net.ssl.SSLSocket) {
            String applicationProtocol = ((org.openjsse.javax.net.ssl.SSLSocket) sslSocket).getApplicationProtocol();
            if (applicationProtocol != null && !Intrinsics.areEqual(applicationProtocol, "")) {
                return applicationProtocol;
            }
        } else {
            super.mo5234h(sslSocket);
        }
        return null;
    }

    @Override // p458k.p459p0.p467k.C4463g
    @NotNull
    /* renamed from: n */
    public SSLContext mo5245n() {
        SSLContext sSLContext = SSLContext.getInstance(NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3, this.f11985f);
        Intrinsics.checkExpressionValueIsNotNull(sSLContext, "SSLContext.getInstance(\"TLSv1.3\", provider)");
        return sSLContext;
    }

    @Override // p458k.p459p0.p467k.C4463g
    @NotNull
    /* renamed from: o */
    public X509TrustManager mo5246o() {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(), this.f11985f);
        factory.init((KeyStore) null);
        Intrinsics.checkExpressionValueIsNotNull(factory, "factory");
        TrustManager[] trustManagers = factory.getTrustManagers();
        if (trustManagers == null) {
            Intrinsics.throwNpe();
        }
        if (trustManagers.length == 1 && (trustManagers[0] instanceof X509TrustManager)) {
            TrustManager trustManager = trustManagers[0];
            if (trustManager != null) {
                return (X509TrustManager) trustManager;
            }
            throw new TypeCastException("null cannot be cast to non-null type javax.net.ssl.X509TrustManager");
        }
        StringBuilder m586H = C1499a.m586H("Unexpected default trust managers: ");
        String arrays = Arrays.toString(trustManagers);
        Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
        m586H.append(arrays);
        throw new IllegalStateException(m586H.toString().toString());
    }
}
