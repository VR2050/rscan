package p458k.p459p0.p467k;

import android.os.Build;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.EnumC4377e0;
import p458k.p459p0.p467k.C4459c;
import p458k.p459p0.p467k.p468h.C4466c;
import p458k.p459p0.p467k.p468h.C4468e;
import p458k.p459p0.p467k.p468h.C4469f;
import p458k.p459p0.p467k.p468h.C4470g;
import p458k.p459p0.p467k.p468h.C4472i;
import p458k.p459p0.p467k.p468h.InterfaceC4471h;
import p458k.p459p0.p470m.AbstractC4476c;
import p458k.p459p0.p470m.InterfaceC4478e;

/* renamed from: k.p0.k.b */
/* loaded from: classes3.dex */
public final class C4458b extends C4463g {

    /* renamed from: d */
    public static final boolean f11962d;

    /* renamed from: e */
    public static final boolean f11963e;

    /* renamed from: f */
    public static final a f11964f = new a(null);

    /* renamed from: g */
    public final List<InterfaceC4471h> f11965g;

    /* renamed from: h */
    public final C4468e f11966h;

    /* renamed from: k.p0.k.b$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    /* renamed from: k.p0.k.b$b */
    public static final class b implements InterfaceC4478e {

        /* renamed from: a */
        public final X509TrustManager f11967a;

        /* renamed from: b */
        public final Method f11968b;

        public b(@NotNull X509TrustManager trustManager, @NotNull Method findByIssuerAndSignatureMethod) {
            Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
            Intrinsics.checkParameterIsNotNull(findByIssuerAndSignatureMethod, "findByIssuerAndSignatureMethod");
            this.f11967a = trustManager;
            this.f11968b = findByIssuerAndSignatureMethod;
        }

        @Override // p458k.p459p0.p470m.InterfaceC4478e
        @Nullable
        /* renamed from: a */
        public X509Certificate mo5242a(@NotNull X509Certificate cert) {
            Intrinsics.checkParameterIsNotNull(cert, "cert");
            try {
                Object invoke = this.f11968b.invoke(this.f11967a, cert);
                if (invoke != null) {
                    return ((TrustAnchor) invoke).getTrustedCert();
                }
                throw new TypeCastException("null cannot be cast to non-null type java.security.cert.TrustAnchor");
            } catch (IllegalAccessException e2) {
                throw new AssertionError("unable to get issues and signature", e2);
            } catch (InvocationTargetException unused) {
                return null;
            }
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof b)) {
                return false;
            }
            b bVar = (b) obj;
            return Intrinsics.areEqual(this.f11967a, bVar.f11967a) && Intrinsics.areEqual(this.f11968b, bVar.f11968b);
        }

        public int hashCode() {
            X509TrustManager x509TrustManager = this.f11967a;
            int hashCode = (x509TrustManager != null ? x509TrustManager.hashCode() : 0) * 31;
            Method method = this.f11968b;
            return hashCode + (method != null ? method.hashCode() : 0);
        }

        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("CustomTrustRootIndex(trustManager=");
            m586H.append(this.f11967a);
            m586H.append(", findByIssuerAndSignatureMethod=");
            m586H.append(this.f11968b);
            m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
            return m586H.toString();
        }
    }

    static {
        boolean z;
        try {
            Class.forName("com.android.org.conscrypt.OpenSSLSocketImpl");
            z = true;
        } catch (ClassNotFoundException | UnsatisfiedLinkError unused) {
            z = false;
        }
        f11962d = z;
        f11963e = z;
    }

    public C4458b() {
        C4472i c4472i;
        Method method;
        Method method2;
        InterfaceC4471h[] interfaceC4471hArr = new InterfaceC4471h[3];
        Intrinsics.checkParameterIsNotNull("com.android.org.conscrypt", "packageName");
        Method method3 = null;
        try {
            Class<?> cls = Class.forName("com.android.org.conscrypt.OpenSSLSocketImpl");
            Class<?> cls2 = Class.forName("com.android.org.conscrypt.OpenSSLSocketFactoryImpl");
            Class<?> paramsClass = Class.forName("com.android.org.conscrypt.SSLParametersImpl");
            Intrinsics.checkExpressionValueIsNotNull(paramsClass, "paramsClass");
            c4472i = new C4472i(cls, cls2, paramsClass);
        } catch (Exception e2) {
            C2354n.m2476g(5, "unable to load android socket classes", e2);
            c4472i = null;
        }
        interfaceC4471hArr[0] = c4472i;
        C4459c.a aVar = C4459c.f11970e;
        interfaceC4471hArr[1] = C4459c.f11969d ? new C4469f() : null;
        interfaceC4471hArr[2] = new C4470g("com.google.android.gms.org.conscrypt");
        List listOfNotNull = CollectionsKt__CollectionsKt.listOfNotNull((Object[]) interfaceC4471hArr);
        ArrayList arrayList = new ArrayList();
        for (Object obj : listOfNotNull) {
            if (((InterfaceC4471h) obj).mo5252a()) {
                arrayList.add(obj);
            }
        }
        this.f11965g = arrayList;
        try {
            Class<?> cls3 = Class.forName("dalvik.system.CloseGuard");
            Method method4 = cls3.getMethod("get", new Class[0]);
            method2 = cls3.getMethod("open", String.class);
            method = cls3.getMethod("warnIfOpen", new Class[0]);
            method3 = method4;
        } catch (Exception unused) {
            method = null;
            method2 = null;
        }
        this.f11966h = new C4468e(method3, method2, method);
    }

    @Override // p458k.p459p0.p467k.C4463g
    @NotNull
    /* renamed from: b */
    public AbstractC4476c mo5232b(@NotNull X509TrustManager trustManager) {
        C4466c c4466c;
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        try {
            Class<?> cls = Class.forName("android.net.http.X509TrustManagerExtensions");
            Object extensions = cls.getConstructor(X509TrustManager.class).newInstance(trustManager);
            Method checkServerTrusted = cls.getMethod("checkServerTrusted", X509Certificate[].class, String.class, String.class);
            Intrinsics.checkExpressionValueIsNotNull(extensions, "extensions");
            Intrinsics.checkExpressionValueIsNotNull(checkServerTrusted, "checkServerTrusted");
            c4466c = new C4466c(trustManager, extensions, checkServerTrusted);
        } catch (Exception unused) {
            c4466c = null;
        }
        return c4466c != null ? c4466c : super.mo5232b(trustManager);
    }

    @Override // p458k.p459p0.p467k.C4463g
    @NotNull
    /* renamed from: c */
    public InterfaceC4478e mo5237c(@NotNull X509TrustManager trustManager) {
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        try {
            Method method = trustManager.getClass().getDeclaredMethod("findTrustAnchorByIssuerAndSignature", X509Certificate.class);
            Intrinsics.checkExpressionValueIsNotNull(method, "method");
            method.setAccessible(true);
            return new b(trustManager, method);
        } catch (NoSuchMethodException unused) {
            return super.mo5237c(trustManager);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: e */
    public void mo5233e(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<EnumC4377e0> protocols) {
        Object obj;
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        Iterator<T> it = this.f11965g.iterator();
        while (true) {
            if (!it.hasNext()) {
                obj = null;
                break;
            } else {
                obj = it.next();
                if (((InterfaceC4471h) obj).mo5254c(sslSocket)) {
                    break;
                }
            }
        }
        InterfaceC4471h interfaceC4471h = (InterfaceC4471h) obj;
        if (interfaceC4471h != null) {
            interfaceC4471h.mo5255d(sslSocket, str, protocols);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: g */
    public void mo5238g(@NotNull Socket socket, @NotNull InetSocketAddress address, int i2) {
        Intrinsics.checkParameterIsNotNull(socket, "socket");
        Intrinsics.checkParameterIsNotNull(address, "address");
        try {
            socket.connect(address, i2);
        } catch (ClassCastException e2) {
            if (Build.VERSION.SDK_INT != 26) {
                throw e2;
            }
            throw new IOException("Exception in connect", e2);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    @Nullable
    /* renamed from: h */
    public String mo5234h(@NotNull SSLSocket sslSocket) {
        Object obj;
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Iterator<T> it = this.f11965g.iterator();
        while (true) {
            if (!it.hasNext()) {
                obj = null;
                break;
            }
            obj = it.next();
            if (((InterfaceC4471h) obj).mo5254c(sslSocket)) {
                break;
            }
        }
        InterfaceC4471h interfaceC4471h = (InterfaceC4471h) obj;
        if (interfaceC4471h != null) {
            return interfaceC4471h.mo5253b(sslSocket);
        }
        return null;
    }

    @Override // p458k.p459p0.p467k.C4463g
    @Nullable
    /* renamed from: i */
    public Object mo5239i(@NotNull String closer) {
        Intrinsics.checkParameterIsNotNull(closer, "closer");
        C4468e c4468e = this.f11966h;
        Objects.requireNonNull(c4468e);
        Intrinsics.checkParameterIsNotNull(closer, "closer");
        Method method = c4468e.f12000a;
        if (method == null) {
            return null;
        }
        try {
            Object invoke = method.invoke(null, new Object[0]);
            Method method2 = c4468e.f12001b;
            if (method2 == null) {
                Intrinsics.throwNpe();
            }
            method2.invoke(invoke, closer);
            return invoke;
        } catch (Exception unused) {
            return null;
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: j */
    public boolean mo5235j(@NotNull String hostname) {
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        try {
            Class<?> networkPolicyClass = Class.forName("android.security.NetworkSecurityPolicy");
            Object networkSecurityPolicy = networkPolicyClass.getMethod("getInstance", new Class[0]).invoke(null, new Object[0]);
            Intrinsics.checkExpressionValueIsNotNull(networkPolicyClass, "networkPolicyClass");
            Intrinsics.checkExpressionValueIsNotNull(networkSecurityPolicy, "networkSecurityPolicy");
            return m5241p(hostname, networkPolicyClass, networkSecurityPolicy);
        } catch (ClassNotFoundException unused) {
            super.mo5235j(hostname);
            return true;
        } catch (IllegalAccessException e2) {
            throw new AssertionError("unable to determine cleartext support", e2);
        } catch (IllegalArgumentException e3) {
            throw new AssertionError("unable to determine cleartext support", e3);
        } catch (NoSuchMethodException unused2) {
            super.mo5235j(hostname);
            return true;
        } catch (InvocationTargetException e4) {
            throw new AssertionError("unable to determine cleartext support", e4);
        }
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: k */
    public void mo5236k(@NotNull String message, int i2, @Nullable Throwable th) {
        Intrinsics.checkParameterIsNotNull(message, "message");
        C2354n.m2476g(i2, message, th);
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: m */
    public void mo5240m(@NotNull String message, @Nullable Object obj) {
        Intrinsics.checkParameterIsNotNull(message, "message");
        C4468e c4468e = this.f11966h;
        Objects.requireNonNull(c4468e);
        boolean z = false;
        if (obj != null) {
            try {
                Method method = c4468e.f12002c;
                if (method == null) {
                    Intrinsics.throwNpe();
                }
                method.invoke(obj, new Object[0]);
                z = true;
            } catch (Exception unused) {
            }
        }
        if (z) {
            return;
        }
        C4463g.m5248l(this, message, 5, null, 4, null);
    }

    /* renamed from: p */
    public final boolean m5241p(String str, Class<?> cls, Object obj) {
        boolean z = true;
        try {
            try {
                Object invoke = cls.getMethod("isCleartextTrafficPermitted", String.class).invoke(obj, str);
                if (invoke != null) {
                    return ((Boolean) invoke).booleanValue();
                }
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Boolean");
            } catch (NoSuchMethodException unused) {
                super.mo5235j(str);
                return z;
            }
        } catch (NoSuchMethodException unused2) {
            Object invoke2 = cls.getMethod("isCleartextTrafficPermitted", new Class[0]).invoke(obj, new Object[0]);
            if (invoke2 == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Boolean");
            }
            z = ((Boolean) invoke2).booleanValue();
            return z;
        }
    }
}
