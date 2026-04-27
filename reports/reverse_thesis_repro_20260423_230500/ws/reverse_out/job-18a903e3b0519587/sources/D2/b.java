package D2;

import B2.B;
import B2.C0163a;
import B2.C0170h;
import B2.D;
import B2.F;
import B2.InterfaceC0164b;
import B2.o;
import B2.q;
import B2.u;
import i2.AbstractC0586n;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class b implements InterfaceC0164b {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final q f608d;

    public b(q qVar) {
        j.f(qVar, "defaultDns");
        this.f608d = qVar;
    }

    private final InetAddress b(Proxy proxy, u uVar, q qVar) {
        Proxy.Type type = proxy.type();
        if (type != null && a.f607a[type.ordinal()] == 1) {
            return (InetAddress) AbstractC0586n.E(qVar.a(uVar.h()));
        }
        SocketAddress socketAddressAddress = proxy.address();
        if (socketAddressAddress == null) {
            throw new NullPointerException("null cannot be cast to non-null type java.net.InetSocketAddress");
        }
        InetAddress address = ((InetSocketAddress) socketAddressAddress).getAddress();
        j.e(address, "(address() as InetSocketAddress).address");
        return address;
    }

    @Override // B2.InterfaceC0164b
    public B a(F f3, D d3) {
        Proxy proxyB;
        q qVarC;
        PasswordAuthentication passwordAuthenticationRequestPasswordAuthentication;
        C0163a c0163aA;
        j.f(d3, "response");
        List<C0170h> listY = d3.y();
        B bY0 = d3.y0();
        u uVarL = bY0.l();
        boolean z3 = d3.A() == 407;
        if (f3 == null || (proxyB = f3.b()) == null) {
            proxyB = Proxy.NO_PROXY;
        }
        for (C0170h c0170h : listY) {
            if (g.j("Basic", c0170h.c(), true)) {
                if (f3 == null || (c0163aA = f3.a()) == null || (qVarC = c0163aA.c()) == null) {
                    qVarC = this.f608d;
                }
                if (z3) {
                    SocketAddress socketAddressAddress = proxyB.address();
                    if (socketAddressAddress == null) {
                        throw new NullPointerException("null cannot be cast to non-null type java.net.InetSocketAddress");
                    }
                    InetSocketAddress inetSocketAddress = (InetSocketAddress) socketAddressAddress;
                    String hostName = inetSocketAddress.getHostName();
                    j.e(proxyB, "proxy");
                    passwordAuthenticationRequestPasswordAuthentication = Authenticator.requestPasswordAuthentication(hostName, b(proxyB, uVarL, qVarC), inetSocketAddress.getPort(), uVarL.p(), c0170h.b(), c0170h.c(), uVarL.r(), Authenticator.RequestorType.PROXY);
                } else {
                    String strH = uVarL.h();
                    j.e(proxyB, "proxy");
                    passwordAuthenticationRequestPasswordAuthentication = Authenticator.requestPasswordAuthentication(strH, b(proxyB, uVarL, qVarC), uVarL.l(), uVarL.p(), c0170h.b(), c0170h.c(), uVarL.r(), Authenticator.RequestorType.SERVER);
                }
                if (passwordAuthenticationRequestPasswordAuthentication != null) {
                    String str = z3 ? "Proxy-Authorization" : "Authorization";
                    String userName = passwordAuthenticationRequestPasswordAuthentication.getUserName();
                    j.e(userName, "auth.userName");
                    char[] password = passwordAuthenticationRequestPasswordAuthentication.getPassword();
                    j.e(password, "auth.password");
                    return bY0.i().e(str, o.a(userName, new String(password), c0170h.a())).b();
                }
            }
        }
        return null;
    }

    public /* synthetic */ b(q qVar, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? q.f398a : qVar);
    }
}
