package B2;

import B2.u;
import java.net.Proxy;
import java.net.ProxySelector;
import java.util.List;
import java.util.Objects;
import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;

/* JADX INFO: renamed from: B2.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0163a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final u f146a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final List f147b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final List f148c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final q f149d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final SocketFactory f150e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final SSLSocketFactory f151f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final HostnameVerifier f152g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final C0169g f153h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final InterfaceC0164b f154i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Proxy f155j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final ProxySelector f156k;

    public C0163a(String str, int i3, q qVar, SocketFactory socketFactory, SSLSocketFactory sSLSocketFactory, HostnameVerifier hostnameVerifier, C0169g c0169g, InterfaceC0164b interfaceC0164b, Proxy proxy, List list, List list2, ProxySelector proxySelector) {
        t2.j.f(str, "uriHost");
        t2.j.f(qVar, "dns");
        t2.j.f(socketFactory, "socketFactory");
        t2.j.f(interfaceC0164b, "proxyAuthenticator");
        t2.j.f(list, "protocols");
        t2.j.f(list2, "connectionSpecs");
        t2.j.f(proxySelector, "proxySelector");
        this.f149d = qVar;
        this.f150e = socketFactory;
        this.f151f = sSLSocketFactory;
        this.f152g = hostnameVerifier;
        this.f153h = c0169g;
        this.f154i = interfaceC0164b;
        this.f155j = proxy;
        this.f156k = proxySelector;
        this.f146a = new u.a().o(sSLSocketFactory != null ? "https" : "http").e(str).k(i3).a();
        this.f147b = C2.c.R(list);
        this.f148c = C2.c.R(list2);
    }

    public final C0169g a() {
        return this.f153h;
    }

    public final List b() {
        return this.f148c;
    }

    public final q c() {
        return this.f149d;
    }

    public final boolean d(C0163a c0163a) {
        t2.j.f(c0163a, "that");
        return t2.j.b(this.f149d, c0163a.f149d) && t2.j.b(this.f154i, c0163a.f154i) && t2.j.b(this.f147b, c0163a.f147b) && t2.j.b(this.f148c, c0163a.f148c) && t2.j.b(this.f156k, c0163a.f156k) && t2.j.b(this.f155j, c0163a.f155j) && t2.j.b(this.f151f, c0163a.f151f) && t2.j.b(this.f152g, c0163a.f152g) && t2.j.b(this.f153h, c0163a.f153h) && this.f146a.l() == c0163a.f146a.l();
    }

    public final HostnameVerifier e() {
        return this.f152g;
    }

    public boolean equals(Object obj) {
        if (obj instanceof C0163a) {
            C0163a c0163a = (C0163a) obj;
            if (t2.j.b(this.f146a, c0163a.f146a) && d(c0163a)) {
                return true;
            }
        }
        return false;
    }

    public final List f() {
        return this.f147b;
    }

    public final Proxy g() {
        return this.f155j;
    }

    public final InterfaceC0164b h() {
        return this.f154i;
    }

    public int hashCode() {
        return ((((((((((((((((((527 + this.f146a.hashCode()) * 31) + this.f149d.hashCode()) * 31) + this.f154i.hashCode()) * 31) + this.f147b.hashCode()) * 31) + this.f148c.hashCode()) * 31) + this.f156k.hashCode()) * 31) + Objects.hashCode(this.f155j)) * 31) + Objects.hashCode(this.f151f)) * 31) + Objects.hashCode(this.f152g)) * 31) + Objects.hashCode(this.f153h);
    }

    public final ProxySelector i() {
        return this.f156k;
    }

    public final SocketFactory j() {
        return this.f150e;
    }

    public final SSLSocketFactory k() {
        return this.f151f;
    }

    public final u l() {
        return this.f146a;
    }

    public String toString() {
        StringBuilder sb;
        Object obj;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("Address{");
        sb2.append(this.f146a.h());
        sb2.append(':');
        sb2.append(this.f146a.l());
        sb2.append(", ");
        if (this.f155j != null) {
            sb = new StringBuilder();
            sb.append("proxy=");
            obj = this.f155j;
        } else {
            sb = new StringBuilder();
            sb.append("proxySelector=");
            obj = this.f156k;
        }
        sb.append(obj);
        sb2.append(sb.toString());
        sb2.append("}");
        return sb2.toString();
    }
}
