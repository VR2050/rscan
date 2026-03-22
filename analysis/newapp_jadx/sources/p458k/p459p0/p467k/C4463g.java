package p458k.p459p0.p467k;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.EnumC4377e0;
import p458k.p459p0.p470m.AbstractC4476c;
import p458k.p459p0.p470m.C4474a;
import p458k.p459p0.p470m.C4475b;
import p458k.p459p0.p470m.InterfaceC4478e;
import p474l.C4744f;

/* renamed from: k.p0.k.g */
/* loaded from: classes3.dex */
public class C4463g {

    /* renamed from: a */
    public static volatile C4463g f11986a;

    /* renamed from: b */
    public static final Logger f11987b;

    /* renamed from: c */
    public static final a f11988c;

    /* renamed from: k.p0.k.g$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        @NotNull
        /* renamed from: a */
        public final List<String> m5249a(@NotNull List<? extends EnumC4377e0> protocols) {
            Intrinsics.checkParameterIsNotNull(protocols, "protocols");
            ArrayList arrayList = new ArrayList();
            for (Object obj : protocols) {
                if (((EnumC4377e0) obj) != EnumC4377e0.HTTP_1_0) {
                    arrayList.add(obj);
                }
            }
            ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                arrayList2.add(((EnumC4377e0) it.next()).f11430l);
            }
            return arrayList2;
        }

        @NotNull
        /* renamed from: b */
        public final byte[] m5250b(@NotNull List<? extends EnumC4377e0> protocols) {
            Intrinsics.checkParameterIsNotNull(protocols, "protocols");
            C4744f c4744f = new C4744f();
            Iterator it = ((ArrayList) m5249a(protocols)).iterator();
            while (it.hasNext()) {
                String str = (String) it.next();
                c4744f.m5374a0(str.length());
                c4744f.m5381f0(str);
            }
            return c4744f.mo5386l();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0052, code lost:
    
        if (r0 != null) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0078, code lost:
    
        if (r0 != null) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00a0, code lost:
    
        if (java.lang.Integer.parseInt(r0) >= 9) goto L45;
     */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0109  */
    static {
        /*
            Method dump skipped, instructions count: 285
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p467k.C4463g.<clinit>():void");
    }

    /* renamed from: l */
    public static /* synthetic */ void m5248l(C4463g c4463g, String str, int i2, Throwable th, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i2 = 4;
        }
        int i4 = i3 & 4;
        c4463g.mo5236k(str, i2, null);
    }

    /* renamed from: a */
    public void mo5247a(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
    }

    @NotNull
    /* renamed from: b */
    public AbstractC4476c mo5232b(@NotNull X509TrustManager trustManager) {
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        return new C4474a(mo5237c(trustManager));
    }

    @NotNull
    /* renamed from: c */
    public InterfaceC4478e mo5237c(@NotNull X509TrustManager trustManager) {
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        Intrinsics.checkExpressionValueIsNotNull(acceptedIssuers, "trustManager.acceptedIssuers");
        return new C4475b((X509Certificate[]) Arrays.copyOf(acceptedIssuers, acceptedIssuers.length));
    }

    /* renamed from: d */
    public void mo5243d(@NotNull SSLSocketFactory socketFactory) {
        Intrinsics.checkParameterIsNotNull(socketFactory, "socketFactory");
    }

    /* renamed from: e */
    public void mo5233e(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
    }

    /* renamed from: f */
    public void mo5244f(@Nullable X509TrustManager x509TrustManager) {
    }

    /* renamed from: g */
    public void mo5238g(@NotNull Socket socket, @NotNull InetSocketAddress address, int i2) {
        Intrinsics.checkParameterIsNotNull(socket, "socket");
        Intrinsics.checkParameterIsNotNull(address, "address");
        socket.connect(address, i2);
    }

    @Nullable
    /* renamed from: h */
    public String mo5234h(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        return null;
    }

    @Nullable
    /* renamed from: i */
    public Object mo5239i(@NotNull String closer) {
        Intrinsics.checkParameterIsNotNull(closer, "closer");
        if (f11987b.isLoggable(Level.FINE)) {
            return new Throwable(closer);
        }
        return null;
    }

    /* renamed from: j */
    public boolean mo5235j(@NotNull String hostname) {
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        return true;
    }

    /* renamed from: k */
    public void mo5236k(@NotNull String message, int i2, @Nullable Throwable th) {
        Intrinsics.checkParameterIsNotNull(message, "message");
        f11987b.log(i2 == 5 ? Level.WARNING : Level.INFO, message, th);
    }

    /* renamed from: m */
    public void mo5240m(@NotNull String message, @Nullable Object obj) {
        Intrinsics.checkParameterIsNotNull(message, "message");
        if (obj == null) {
            message = C1499a.m637w(message, " To see where this was allocated, set the OkHttpClient logger level to FINE: Logger.getLogger(OkHttpClient.class.getName()).setLevel(Level.FINE);");
        }
        mo5236k(message, 5, (Throwable) obj);
    }

    @NotNull
    /* renamed from: n */
    public SSLContext mo5245n() {
        SSLContext sSLContext = SSLContext.getInstance("TLS");
        Intrinsics.checkExpressionValueIsNotNull(sSLContext, "SSLContext.getInstance(\"TLS\")");
        return sSLContext;
    }

    @NotNull
    /* renamed from: o */
    public X509TrustManager mo5246o() {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
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

    @NotNull
    public String toString() {
        String simpleName = getClass().getSimpleName();
        Intrinsics.checkExpressionValueIsNotNull(simpleName, "javaClass.simpleName");
        return simpleName;
    }
}
