package B2;

import java.net.InetSocketAddress;
import java.net.Proxy;

/* JADX INFO: loaded from: classes.dex */
public final class F {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final C0163a f135a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Proxy f136b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final InetSocketAddress f137c;

    public F(C0163a c0163a, Proxy proxy, InetSocketAddress inetSocketAddress) {
        t2.j.f(c0163a, "address");
        t2.j.f(proxy, "proxy");
        t2.j.f(inetSocketAddress, "socketAddress");
        this.f135a = c0163a;
        this.f136b = proxy;
        this.f137c = inetSocketAddress;
    }

    public final C0163a a() {
        return this.f135a;
    }

    public final Proxy b() {
        return this.f136b;
    }

    public final boolean c() {
        return this.f135a.k() != null && this.f136b.type() == Proxy.Type.HTTP;
    }

    public final InetSocketAddress d() {
        return this.f137c;
    }

    public boolean equals(Object obj) {
        if (obj instanceof F) {
            F f3 = (F) obj;
            if (t2.j.b(f3.f135a, this.f135a) && t2.j.b(f3.f136b, this.f136b) && t2.j.b(f3.f137c, this.f137c)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return ((((527 + this.f135a.hashCode()) * 31) + this.f136b.hashCode()) * 31) + this.f137c.hashCode();
    }

    public String toString() {
        return "Route{" + this.f137c + '}';
    }
}
