package p458k;

import java.net.Proxy;
import java.net.ProxySelector;
import java.util.List;
import java.util.Objects;
import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.C4489z;
import p458k.p459p0.C4401c;

/* renamed from: k.a */
/* loaded from: classes3.dex */
public final class C4368a {

    /* renamed from: a */
    @NotNull
    public final C4489z f11296a;

    /* renamed from: b */
    @NotNull
    public final List<EnumC4377e0> f11297b;

    /* renamed from: c */
    @NotNull
    public final List<C4392m> f11298c;

    /* renamed from: d */
    @NotNull
    public final InterfaceC4484u f11299d;

    /* renamed from: e */
    @NotNull
    public final SocketFactory f11300e;

    /* renamed from: f */
    @Nullable
    public final SSLSocketFactory f11301f;

    /* renamed from: g */
    @Nullable
    public final HostnameVerifier f11302g;

    /* renamed from: h */
    @Nullable
    public final C4382h f11303h;

    /* renamed from: i */
    @NotNull
    public final InterfaceC4372c f11304i;

    /* renamed from: j */
    @Nullable
    public final Proxy f11305j;

    /* renamed from: k */
    @NotNull
    public final ProxySelector f11306k;

    public C4368a(@NotNull String host, int i2, @NotNull InterfaceC4484u dns, @NotNull SocketFactory socketFactory, @Nullable SSLSocketFactory sSLSocketFactory, @Nullable HostnameVerifier hostnameVerifier, @Nullable C4382h c4382h, @NotNull InterfaceC4372c proxyAuthenticator, @Nullable Proxy proxy, @NotNull List<? extends EnumC4377e0> protocols, @NotNull List<C4392m> connectionSpecs, @NotNull ProxySelector proxySelector) {
        Intrinsics.checkParameterIsNotNull(host, "uriHost");
        Intrinsics.checkParameterIsNotNull(dns, "dns");
        Intrinsics.checkParameterIsNotNull(socketFactory, "socketFactory");
        Intrinsics.checkParameterIsNotNull(proxyAuthenticator, "proxyAuthenticator");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        Intrinsics.checkParameterIsNotNull(connectionSpecs, "connectionSpecs");
        Intrinsics.checkParameterIsNotNull(proxySelector, "proxySelector");
        this.f11299d = dns;
        this.f11300e = socketFactory;
        this.f11301f = sSLSocketFactory;
        this.f11302g = hostnameVerifier;
        this.f11303h = c4382h;
        this.f11304i = proxyAuthenticator;
        this.f11305j = null;
        this.f11306k = proxySelector;
        C4489z.a aVar = new C4489z.a();
        String scheme = sSLSocketFactory != null ? "https" : "http";
        Intrinsics.checkParameterIsNotNull(scheme, "scheme");
        if (StringsKt__StringsJVMKt.equals(scheme, "http", true)) {
            aVar.f12056b = "http";
        } else {
            if (!StringsKt__StringsJVMKt.equals(scheme, "https", true)) {
                throw new IllegalArgumentException(C1499a.m637w("unexpected scheme: ", scheme));
            }
            aVar.f12056b = "https";
        }
        Intrinsics.checkParameterIsNotNull(host, "host");
        String m2433T1 = C2354n.m2433T1(C4489z.b.m5304e(C4489z.f12044b, host, 0, 0, false, 7));
        if (m2433T1 == null) {
            throw new IllegalArgumentException(C1499a.m637w("unexpected host: ", host));
        }
        aVar.f12059e = m2433T1;
        if (!(1 <= i2 && 65535 >= i2)) {
            throw new IllegalArgumentException(C1499a.m626l("unexpected port: ", i2).toString());
        }
        aVar.f12060f = i2;
        this.f11296a = aVar.m5299a();
        this.f11297b = C4401c.m5038w(protocols);
        this.f11298c = C4401c.m5038w(connectionSpecs);
    }

    /* renamed from: a */
    public final boolean m4940a(@NotNull C4368a that) {
        Intrinsics.checkParameterIsNotNull(that, "that");
        return Intrinsics.areEqual(this.f11299d, that.f11299d) && Intrinsics.areEqual(this.f11304i, that.f11304i) && Intrinsics.areEqual(this.f11297b, that.f11297b) && Intrinsics.areEqual(this.f11298c, that.f11298c) && Intrinsics.areEqual(this.f11306k, that.f11306k) && Intrinsics.areEqual(this.f11305j, that.f11305j) && Intrinsics.areEqual(this.f11301f, that.f11301f) && Intrinsics.areEqual(this.f11302g, that.f11302g) && Intrinsics.areEqual(this.f11303h, that.f11303h) && this.f11296a.f12050h == that.f11296a.f12050h;
    }

    public boolean equals(@Nullable Object obj) {
        if (obj instanceof C4368a) {
            C4368a c4368a = (C4368a) obj;
            if (Intrinsics.areEqual(this.f11296a, c4368a.f11296a) && m4940a(c4368a)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return Objects.hashCode(this.f11303h) + ((Objects.hashCode(this.f11302g) + ((Objects.hashCode(this.f11301f) + ((Objects.hashCode(this.f11305j) + ((this.f11306k.hashCode() + ((this.f11298c.hashCode() + ((this.f11297b.hashCode() + ((this.f11304i.hashCode() + ((this.f11299d.hashCode() + ((this.f11296a.hashCode() + 527) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H;
        Object obj;
        StringBuilder m586H2 = C1499a.m586H("Address{");
        m586H2.append(this.f11296a.f12049g);
        m586H2.append(':');
        m586H2.append(this.f11296a.f12050h);
        m586H2.append(", ");
        if (this.f11305j != null) {
            m586H = C1499a.m586H("proxy=");
            obj = this.f11305j;
        } else {
            m586H = C1499a.m586H("proxySelector=");
            obj = this.f11306k;
        }
        m586H.append(obj);
        m586H2.append(m586H.toString());
        m586H2.append("}");
        return m586H2.toString();
    }
}
