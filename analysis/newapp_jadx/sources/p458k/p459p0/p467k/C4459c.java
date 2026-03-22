package p458k.p459p0.p467k;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.conscrypt.Conscrypt;
import org.conscrypt.ConscryptHostnameVerifier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.EnumC4377e0;

/* renamed from: k.p0.k.c */
/* loaded from: classes3.dex */
public final class C4459c extends C4463g {

    /* renamed from: d */
    public static final boolean f11969d;

    /* renamed from: e */
    public static final a f11970e;

    /* renamed from: f */
    public final Provider f11971f;

    /* renamed from: k.p0.k.c$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    /* renamed from: k.p0.k.c$b */
    public static final class b implements ConscryptHostnameVerifier {

        /* renamed from: c */
        public static final b f11972c = new b();

        @Override // org.conscrypt.ConscryptHostnameVerifier
        public final boolean verify(String str, SSLSession sSLSession) {
            return true;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x003e, code lost:
    
        if (r0.patch() >= 0) goto L9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x0027, code lost:
    
        if (r0.major() > 2) goto L9;
     */
    static {
        /*
            k.p0.k.c$a r0 = new k.p0.k.c$a
            r1 = 0
            r0.<init>(r1)
            p458k.p459p0.p467k.C4459c.f11970e = r0
            r1 = 0
            java.lang.String r2 = "org.conscrypt.Conscrypt$Version"
            java.lang.Class.forName(r2)     // Catch: java.lang.ClassNotFoundException -> L44
            boolean r2 = org.conscrypt.Conscrypt.isAvailable()     // Catch: java.lang.ClassNotFoundException -> L44
            r3 = 1
            if (r2 == 0) goto L44
            r2 = 2
            java.util.Objects.requireNonNull(r0)     // Catch: java.lang.ClassNotFoundException -> L44
            org.conscrypt.Conscrypt$Version r0 = org.conscrypt.Conscrypt.version()     // Catch: java.lang.ClassNotFoundException -> L44
            int r4 = r0.major()     // Catch: java.lang.ClassNotFoundException -> L44
            if (r4 == r2) goto L2d
            int r0 = r0.major()     // Catch: java.lang.ClassNotFoundException -> L44
            if (r0 <= r2) goto L2b
        L29:
            r0 = 1
            goto L41
        L2b:
            r0 = 0
            goto L41
        L2d:
            int r2 = r0.minor()     // Catch: java.lang.ClassNotFoundException -> L44
            if (r2 == r3) goto L3a
            int r0 = r0.minor()     // Catch: java.lang.ClassNotFoundException -> L44
            if (r0 <= r3) goto L2b
            goto L29
        L3a:
            int r0 = r0.patch()     // Catch: java.lang.ClassNotFoundException -> L44
            if (r0 < 0) goto L2b
            goto L29
        L41:
            if (r0 == 0) goto L44
            r1 = 1
        L44:
            p458k.p459p0.p467k.C4459c.f11969d = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p467k.C4459c.<clinit>():void");
    }

    public C4459c(DefaultConstructorMarker defaultConstructorMarker) {
        Provider build = Conscrypt.newProviderBuilder().provideTrustManager(true).build();
        Intrinsics.checkExpressionValueIsNotNull(build, "Conscrypt.newProviderBui…rustManager(true).build()");
        this.f11971f = build;
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: d */
    public void mo5243d(@NotNull SSLSocketFactory socketFactory) {
        Intrinsics.checkParameterIsNotNull(socketFactory, "socketFactory");
        if (Conscrypt.isConscrypt(socketFactory)) {
            Conscrypt.setUseEngineSocket(socketFactory, true);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: e */
    public void mo5233e(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        if (!Conscrypt.isConscrypt(sslSocket)) {
            Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
            Intrinsics.checkParameterIsNotNull(protocols, "protocols");
            return;
        }
        Conscrypt.setUseSessionTickets(sslSocket, true);
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
        Object[] array = arrayList2.toArray(new String[0]);
        if (array == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
        }
        Conscrypt.setApplicationProtocols(sslSocket, (String[]) array);
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: f */
    public void mo5244f(@Nullable X509TrustManager x509TrustManager) {
        if (Conscrypt.isConscrypt(x509TrustManager)) {
            Conscrypt.setHostnameVerifier(x509TrustManager, b.f11972c);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    @Nullable
    /* renamed from: h */
    public String mo5234h(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        if (Conscrypt.isConscrypt(sslSocket)) {
            return Conscrypt.getApplicationProtocol(sslSocket);
        }
        super.mo5234h(sslSocket);
        return null;
    }

    @Override // p458k.p459p0.p467k.C4463g
    @NotNull
    /* renamed from: n */
    public SSLContext mo5245n() {
        SSLContext sSLContext = SSLContext.getInstance("TLS", this.f11971f);
        Intrinsics.checkExpressionValueIsNotNull(sSLContext, "SSLContext.getInstance(\"TLS\", provider)");
        return sSLContext;
    }

    @Override // p458k.p459p0.p467k.C4463g
    @NotNull
    /* renamed from: o */
    public X509TrustManager mo5246o() {
        X509TrustManager defaultX509TrustManager = Conscrypt.getDefaultX509TrustManager();
        Intrinsics.checkExpressionValueIsNotNull(defaultX509TrustManager, "Conscrypt.getDefaultX509TrustManager()");
        return defaultX509TrustManager;
    }
}
