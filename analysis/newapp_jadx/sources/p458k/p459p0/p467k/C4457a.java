package p458k.p459p0.p467k;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.security.NetworkSecurityPolicy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.EnumC4377e0;
import p458k.p459p0.p467k.C4458b;
import p458k.p459p0.p467k.C4459c;
import p458k.p459p0.p467k.p468h.C4464a;
import p458k.p459p0.p467k.p468h.C4465b;
import p458k.p459p0.p467k.p468h.C4469f;
import p458k.p459p0.p467k.p468h.C4470g;
import p458k.p459p0.p467k.p468h.InterfaceC4471h;
import p458k.p459p0.p470m.AbstractC4476c;

/* renamed from: k.p0.k.a */
/* loaded from: classes3.dex */
public final class C4457a extends C4463g {

    /* renamed from: d */
    public static final boolean f11959d;

    /* renamed from: e */
    public static final a f11960e = new a(null);

    /* renamed from: f */
    public final List<InterfaceC4471h> f11961f;

    /* renamed from: k.p0.k.a$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    static {
        C4458b.a aVar = C4458b.f11964f;
        f11959d = C4458b.f11962d && Build.VERSION.SDK_INT >= 29;
    }

    public C4457a() {
        InterfaceC4471h[] interfaceC4471hArr = new InterfaceC4471h[3];
        C4458b.a aVar = C4458b.f11964f;
        interfaceC4471hArr[0] = C4458b.f11962d && Build.VERSION.SDK_INT >= 29 ? new C4465b() : null;
        C4459c.a aVar2 = C4459c.f11970e;
        interfaceC4471hArr[1] = C4459c.f11969d ? new C4469f() : null;
        interfaceC4471hArr[2] = new C4470g("com.google.android.gms.org.conscrypt");
        List listOfNotNull = CollectionsKt__CollectionsKt.listOfNotNull((Object[]) interfaceC4471hArr);
        ArrayList arrayList = new ArrayList();
        for (Object obj : listOfNotNull) {
            if (((InterfaceC4471h) obj).mo5252a()) {
                arrayList.add(obj);
            }
        }
        this.f11961f = arrayList;
    }

    @Override // p458k.p459p0.p467k.C4463g
    @NotNull
    /* renamed from: b */
    public AbstractC4476c mo5232b(@NotNull X509TrustManager trustManager) {
        X509TrustManagerExtensions x509TrustManagerExtensions;
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
        try {
            x509TrustManagerExtensions = new X509TrustManagerExtensions(trustManager);
        } catch (IllegalArgumentException unused) {
            x509TrustManagerExtensions = null;
        }
        C4464a c4464a = x509TrustManagerExtensions != null ? new C4464a(trustManager, x509TrustManagerExtensions) : null;
        return c4464a != null ? c4464a : super.mo5232b(trustManager);
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: e */
    public void mo5233e(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<? extends EnumC4377e0> protocols) {
        Object obj;
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        Iterator<T> it = this.f11961f.iterator();
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
    @Nullable
    /* renamed from: h */
    public String mo5234h(@NotNull SSLSocket sslSocket) {
        Object obj;
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Iterator<T> it = this.f11961f.iterator();
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
    /* renamed from: j */
    public boolean mo5235j(@NotNull String hostname) {
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        return NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(hostname);
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: k */
    public void mo5236k(@NotNull String message, int i2, @Nullable Throwable th) {
        Intrinsics.checkParameterIsNotNull(message, "message");
        C2354n.m2476g(i2, message, th);
    }
}
