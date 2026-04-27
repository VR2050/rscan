package G2;

import B2.C0163a;
import B2.F;
import B2.InterfaceC0167e;
import B2.r;
import B2.u;
import i2.AbstractC0586n;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class k {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final a f964i = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private List f965a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f966b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private List f967c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f968d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final C0163a f969e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final i f970f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final InterfaceC0167e f971g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final r f972h;

    public static final class a {
        private a() {
        }

        public final String a(InetSocketAddress inetSocketAddress) {
            t2.j.f(inetSocketAddress, "$this$socketHost");
            InetAddress address = inetSocketAddress.getAddress();
            if (address != null) {
                String hostAddress = address.getHostAddress();
                t2.j.e(hostAddress, "address.hostAddress");
                return hostAddress;
            }
            String hostName = inetSocketAddress.getHostName();
            t2.j.e(hostName, "hostName");
            return hostName;
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f973a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final List f974b;

        public b(List list) {
            t2.j.f(list, "routes");
            this.f974b = list;
        }

        public final List a() {
            return this.f974b;
        }

        public final boolean b() {
            return this.f973a < this.f974b.size();
        }

        public final F c() {
            if (!b()) {
                throw new NoSuchElementException();
            }
            List list = this.f974b;
            int i3 = this.f973a;
            this.f973a = i3 + 1;
            return (F) list.get(i3);
        }
    }

    static final class c extends t2.k implements InterfaceC0688a {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Proxy f976d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ u f977e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        c(Proxy proxy, u uVar) {
            super(0);
            this.f976d = proxy;
            this.f977e = uVar;
        }

        @Override // s2.InterfaceC0688a
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final List a() {
            Proxy proxy = this.f976d;
            if (proxy != null) {
                return AbstractC0586n.b(proxy);
            }
            URI uriQ = this.f977e.q();
            if (uriQ.getHost() == null) {
                return C2.c.t(Proxy.NO_PROXY);
            }
            List<Proxy> listSelect = k.this.f969e.i().select(uriQ);
            return (listSelect == null || listSelect.isEmpty()) ? C2.c.t(Proxy.NO_PROXY) : C2.c.R(listSelect);
        }
    }

    public k(C0163a c0163a, i iVar, InterfaceC0167e interfaceC0167e, r rVar) {
        t2.j.f(c0163a, "address");
        t2.j.f(iVar, "routeDatabase");
        t2.j.f(interfaceC0167e, "call");
        t2.j.f(rVar, "eventListener");
        this.f969e = c0163a;
        this.f970f = iVar;
        this.f971g = interfaceC0167e;
        this.f972h = rVar;
        this.f965a = AbstractC0586n.g();
        this.f967c = AbstractC0586n.g();
        this.f968d = new ArrayList();
        g(c0163a.l(), c0163a.g());
    }

    private final boolean c() {
        return this.f966b < this.f965a.size();
    }

    private final Proxy e() throws SocketException, UnknownHostException {
        if (c()) {
            List list = this.f965a;
            int i3 = this.f966b;
            this.f966b = i3 + 1;
            Proxy proxy = (Proxy) list.get(i3);
            f(proxy);
            return proxy;
        }
        throw new SocketException("No route to " + this.f969e.l().h() + "; exhausted proxy configurations: " + this.f965a);
    }

    private final void f(Proxy proxy) throws SocketException, UnknownHostException {
        String strH;
        int iL;
        ArrayList arrayList = new ArrayList();
        this.f967c = arrayList;
        if (proxy.type() == Proxy.Type.DIRECT || proxy.type() == Proxy.Type.SOCKS) {
            strH = this.f969e.l().h();
            iL = this.f969e.l().l();
        } else {
            SocketAddress socketAddressAddress = proxy.address();
            if (!(socketAddressAddress instanceof InetSocketAddress)) {
                throw new IllegalArgumentException(("Proxy.address() is not an InetSocketAddress: " + socketAddressAddress.getClass()).toString());
            }
            InetSocketAddress inetSocketAddress = (InetSocketAddress) socketAddressAddress;
            strH = f964i.a(inetSocketAddress);
            iL = inetSocketAddress.getPort();
        }
        if (1 > iL || 65535 < iL) {
            throw new SocketException("No route to " + strH + ':' + iL + "; port is out of range");
        }
        if (proxy.type() == Proxy.Type.SOCKS) {
            arrayList.add(InetSocketAddress.createUnresolved(strH, iL));
            return;
        }
        this.f972h.n(this.f971g, strH);
        List listA = this.f969e.c().a(strH);
        if (listA.isEmpty()) {
            throw new UnknownHostException(this.f969e.c() + " returned no addresses for " + strH);
        }
        this.f972h.m(this.f971g, strH, listA);
        Iterator it = listA.iterator();
        while (it.hasNext()) {
            arrayList.add(new InetSocketAddress((InetAddress) it.next(), iL));
        }
    }

    private final void g(u uVar, Proxy proxy) {
        c cVar = new c(proxy, uVar);
        this.f972h.p(this.f971g, uVar);
        List listA = cVar.a();
        this.f965a = listA;
        this.f966b = 0;
        this.f972h.o(this.f971g, uVar, listA);
    }

    public final boolean b() {
        return c() || !this.f968d.isEmpty();
    }

    public final b d() {
        if (!b()) {
            throw new NoSuchElementException();
        }
        ArrayList arrayList = new ArrayList();
        while (c()) {
            Proxy proxyE = e();
            Iterator it = this.f967c.iterator();
            while (it.hasNext()) {
                F f3 = new F(this.f969e, proxyE, (InetSocketAddress) it.next());
                if (this.f970f.c(f3)) {
                    this.f968d.add(f3);
                } else {
                    arrayList.add(f3);
                }
            }
            if (!arrayList.isEmpty()) {
                break;
            }
        }
        if (arrayList.isEmpty()) {
            AbstractC0586n.q(arrayList, this.f968d);
            this.f968d.clear();
        }
        return new b(arrayList);
    }
}
