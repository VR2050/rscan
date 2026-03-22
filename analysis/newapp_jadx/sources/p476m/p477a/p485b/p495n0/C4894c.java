package p476m.p477a.p485b.p495n0;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: m.a.b.n0.c */
/* loaded from: classes3.dex */
public final class C4894c {
    /* renamed from: a */
    public static void m5566a(StringBuilder sb, SocketAddress socketAddress) {
        C2354n.m2470e1(sb, "Buffer");
        C2354n.m2470e1(socketAddress, "Socket address");
        if (!(socketAddress instanceof InetSocketAddress)) {
            sb.append(socketAddress);
            return;
        }
        InetSocketAddress inetSocketAddress = (InetSocketAddress) socketAddress;
        InetAddress address = inetSocketAddress.getAddress();
        String str = address;
        if (address != null) {
            str = address.getHostAddress();
        }
        sb.append((Object) str);
        sb.append(':');
        sb.append(inetSocketAddress.getPort());
    }
}
