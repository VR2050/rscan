package p476m.p477a.p485b.p488j0.p489h;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4796d;
import p476m.p477a.p485b.InterfaceC4900t;
import p476m.p477a.p485b.p486h0.C4806b;
import p476m.p477a.p485b.p488j0.C4814b;
import p476m.p477a.p485b.p488j0.C4815c;
import p476m.p477a.p485b.p488j0.C4817e;
import p476m.p477a.p485b.p494m0.C4875b;
import p476m.p477a.p485b.p494m0.C4883j;
import p476m.p477a.p485b.p494m0.C4884k;
import p476m.p477a.p485b.p494m0.C4885l;
import p476m.p477a.p485b.p494m0.C4886m;
import p476m.p477a.p485b.p494m0.C4887n;
import p476m.p477a.p485b.p494m0.C4888o;
import p476m.p477a.p485b.p494m0.C4889p;
import p476m.p477a.p485b.p494m0.C4890q;
import p476m.p477a.p485b.p494m0.InterfaceC4882i;

/* renamed from: m.a.b.j0.h.d */
/* loaded from: classes3.dex */
public class C4823d {

    /* renamed from: a */
    public int f12346a;

    /* renamed from: b */
    public InetAddress f12347b;

    /* renamed from: c */
    public C4806b f12348c;

    /* renamed from: d */
    public String f12349d;

    /* renamed from: e */
    public Map<String, InterfaceC4882i> f12350e;

    /* renamed from: f */
    public ServerSocketFactory f12351f;

    /* renamed from: g */
    public SSLContext f12352g;

    /* renamed from: h */
    public InterfaceC4822c f12353h;

    /* renamed from: i */
    public InterfaceC4796d f12354i;

    /* renamed from: a */
    public C4820a m5490a() {
        String str = this.f12349d;
        if (str == null) {
            str = "Apache-HttpCore/1.1";
        }
        InterfaceC4900t[] interfaceC4900tArr = {new C4887n(), new C4888o(str), new C4886m(), new C4885l()};
        C4875b c4875b = new C4875b();
        Objects.requireNonNull(c4875b);
        for (int i2 = 0; i2 < 4; i2++) {
            c4875b.m5547a(interfaceC4900tArr[i2]);
        }
        C4884k c4884k = new C4884k(null, c4875b != null ? new LinkedList(c4875b.f12477a) : null);
        C4889p c4889p = new C4889p();
        Map<String, InterfaceC4882i> map = this.f12350e;
        if (map != null) {
            for (Map.Entry<String, InterfaceC4882i> entry : map.entrySet()) {
                String key = entry.getKey();
                InterfaceC4882i value = entry.getValue();
                C2354n.m2470e1(key, "Pattern");
                C2354n.m2470e1(value, "Handler");
                C4890q<InterfaceC4882i> c4890q = c4889p.f12493a;
                synchronized (c4890q) {
                    C2354n.m2470e1(key, "URI request pattern");
                    c4890q.f12494a.put(key, value);
                }
            }
        }
        C4883j c4883j = new C4883j(c4884k, C4815c.f12312a, C4817e.f12316a, c4889p, null);
        ServerSocketFactory serverSocketFactory = this.f12351f;
        if (serverSocketFactory == null) {
            SSLContext sSLContext = this.f12352g;
            serverSocketFactory = sSLContext != null ? sSLContext.getServerSocketFactory() : ServerSocketFactory.getDefault();
        }
        ServerSocketFactory serverSocketFactory2 = serverSocketFactory;
        C4814b c4814b = C4814b.f12311a;
        InterfaceC4796d interfaceC4796d = this.f12354i;
        if (interfaceC4796d == null) {
            interfaceC4796d = InterfaceC4796d.f12282a;
        }
        InterfaceC4796d interfaceC4796d2 = interfaceC4796d;
        int i3 = this.f12346a;
        int i4 = i3 > 0 ? i3 : 0;
        InetAddress inetAddress = this.f12347b;
        C4806b c4806b = this.f12348c;
        if (c4806b == null) {
            c4806b = C4806b.f12286c;
        }
        return new C4820a(i4, inetAddress, c4806b, serverSocketFactory2, c4883j, c4814b, this.f12353h, interfaceC4796d2);
    }
}
