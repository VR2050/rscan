package p005b.p172h.p173a;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/* renamed from: b.h.a.j */
/* loaded from: classes.dex */
public class C1821j extends ProxySelector {

    /* renamed from: a */
    public static final List<Proxy> f2813a = Arrays.asList(Proxy.NO_PROXY);

    /* renamed from: b */
    public final ProxySelector f2814b;

    /* renamed from: c */
    public final String f2815c;

    /* renamed from: d */
    public final int f2816d;

    public C1821j(ProxySelector proxySelector, String str, int i2) {
        Objects.requireNonNull(proxySelector);
        this.f2814b = proxySelector;
        Objects.requireNonNull(str);
        this.f2815c = str;
        this.f2816d = i2;
    }

    @Override // java.net.ProxySelector
    public void connectFailed(URI uri, SocketAddress socketAddress, IOException iOException) {
        this.f2814b.connectFailed(uri, socketAddress, iOException);
    }

    @Override // java.net.ProxySelector
    public List<Proxy> select(URI uri) {
        return this.f2815c.equals(uri.getHost()) && this.f2816d == uri.getPort() ? f2813a : this.f2814b.select(uri);
    }
}
