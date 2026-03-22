package p476m.p477a.p485b.p488j0;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4790a;
import p476m.p477a.p485b.C4791a0;
import p476m.p477a.p485b.C4793b0;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4804h;
import p476m.p477a.p485b.InterfaceC4807i;
import p476m.p477a.p485b.InterfaceC4846k;
import p476m.p477a.p485b.InterfaceC4852l;
import p476m.p477a.p485b.InterfaceC4895o;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4901u;
import p476m.p477a.p485b.p486h0.C4805a;
import p476m.p477a.p485b.p487i0.C4809b;
import p476m.p477a.p485b.p487i0.InterfaceC4811d;
import p476m.p477a.p485b.p488j0.p490i.C4827a;
import p476m.p477a.p485b.p488j0.p490i.C4829c;
import p476m.p477a.p485b.p488j0.p491j.AbstractC4830a;
import p476m.p477a.p485b.p488j0.p491j.AbstractC4831b;
import p476m.p477a.p485b.p488j0.p491j.C4832c;
import p476m.p477a.p485b.p488j0.p491j.C4833d;
import p476m.p477a.p485b.p488j0.p491j.C4834e;
import p476m.p477a.p485b.p488j0.p491j.C4835f;
import p476m.p477a.p485b.p488j0.p491j.C4836g;
import p476m.p477a.p485b.p488j0.p491j.C4837h;
import p476m.p477a.p485b.p488j0.p491j.C4838i;
import p476m.p477a.p485b.p488j0.p491j.C4839j;
import p476m.p477a.p485b.p488j0.p491j.C4840k;
import p476m.p477a.p485b.p488j0.p491j.C4841l;
import p476m.p477a.p485b.p488j0.p491j.C4842m;
import p476m.p477a.p485b.p488j0.p491j.C4843n;
import p476m.p477a.p485b.p488j0.p491j.C4844o;
import p476m.p477a.p485b.p488j0.p491j.C4845p;
import p476m.p477a.p485b.p492k0.InterfaceC4848b;
import p476m.p477a.p485b.p492k0.InterfaceC4849c;
import p476m.p477a.p485b.p492k0.InterfaceC4850d;
import p476m.p477a.p485b.p493l0.AbstractC4853a;
import p476m.p477a.p485b.p493l0.C4859g;
import p476m.p477a.p485b.p493l0.C4860h;
import p476m.p477a.p485b.p493l0.C4862j;
import p476m.p477a.p485b.p495n0.C4893b;
import p476m.p477a.p485b.p495n0.C4894c;

/* renamed from: m.a.b.j0.a */
/* loaded from: classes3.dex */
public class C4813a implements InterfaceC4901u, InterfaceC4807i {

    /* renamed from: c */
    public final C4844o f12302c;

    /* renamed from: e */
    public final C4845p f12303e;

    /* renamed from: f */
    public final C4805a f12304f;

    /* renamed from: g */
    public final C4819g f12305g;

    /* renamed from: h */
    public final InterfaceC4811d f12306h;

    /* renamed from: i */
    public final InterfaceC4811d f12307i;

    /* renamed from: j */
    public final AtomicReference<Socket> f12308j;

    /* renamed from: k */
    public final AbstractC4830a<InterfaceC4895o> f12309k;

    /* renamed from: l */
    public final AbstractC4831b<InterfaceC4898r> f12310l;

    public C4813a(int i2, int i3, CharsetDecoder charsetDecoder, CharsetEncoder charsetEncoder, C4805a c4805a, InterfaceC4811d interfaceC4811d, InterfaceC4811d interfaceC4811d2, InterfaceC4848b<InterfaceC4895o> interfaceC4848b, InterfaceC4849c<InterfaceC4898r> interfaceC4849c) {
        C4827a c4827a = C4827a.f12362a;
        C2354n.m2499n1(i2, "Buffer size");
        C4841l c4841l = new C4841l();
        C4841l c4841l2 = new C4841l();
        C4844o c4844o = new C4844o(c4841l, i2, -1, C4805a.f12283c, null);
        this.f12302c = c4844o;
        C4845p c4845p = new C4845p(c4841l2, i2, i3, null);
        this.f12303e = c4845p;
        this.f12304f = null;
        this.f12305g = new C4819g(c4841l, c4841l2);
        this.f12306h = c4827a;
        this.f12307i = C4829c.f12366a;
        this.f12308j = new AtomicReference<>();
        C4837h c4837h = C4837h.f12400a;
        this.f12309k = new C4836g(c4844o, c4837h.f12401b, c4837h.f12402c, null);
        C4839j c4839j = C4839j.f12403a;
        this.f12310l = new C4838i(c4845p, C4860h.f12449a);
    }

    @Override // p476m.p477a.p485b.InterfaceC4901u
    /* renamed from: L */
    public InterfaceC4895o mo5480L() {
        m5482b();
        AbstractC4830a<InterfaceC4895o> abstractC4830a = this.f12309k;
        Socket socket = this.f12308j.get();
        int i2 = abstractC4830a.f12371e;
        if (i2 == 0) {
            try {
                abstractC4830a.f12372f = abstractC4830a.mo5492a(socket, abstractC4830a.f12367a);
                abstractC4830a.f12371e = 1;
            } catch (C4791a0 e2) {
                throw new C4793b0(e2.getMessage(), e2);
            }
        } else if (i2 != 1) {
            throw new IllegalStateException("Inconsistent parser state");
        }
        InterfaceC4850d interfaceC4850d = abstractC4830a.f12367a;
        C4805a c4805a = abstractC4830a.f12368b;
        abstractC4830a.f12372f.mo5515g(AbstractC4830a.m5491b(interfaceC4850d, c4805a.f12285f, c4805a.f12284e, abstractC4830a.f12370d, abstractC4830a.f12369c));
        InterfaceC4895o interfaceC4895o = abstractC4830a.f12372f;
        abstractC4830a.f12372f = null;
        abstractC4830a.f12369c.clear();
        abstractC4830a.f12371e = 0;
        InterfaceC4895o interfaceC4895o2 = interfaceC4895o;
        this.f12305g.f12320a++;
        return interfaceC4895o2;
    }

    @Override // p476m.p477a.p485b.InterfaceC4901u
    /* renamed from: O */
    public void mo5481O(InterfaceC4852l interfaceC4852l) {
        C2354n.m2470e1(interfaceC4852l, "HTTP request");
        m5482b();
        C4809b c4809b = new C4809b();
        long mo5479a = this.f12306h.mo5479a(interfaceC4852l);
        C4844o c4844o = this.f12302c;
        InputStream c4832c = mo5479a == -2 ? new C4832c(c4844o, this.f12304f) : mo5479a == -1 ? new C4842m(c4844o) : mo5479a == 0 ? C4840k.f12404c : new C4834e(c4844o, mo5479a);
        if (mo5479a == -2) {
            c4809b.f12297f = true;
            c4809b.f12299h = -1L;
            c4809b.f12298g = c4832c;
        } else if (mo5479a == -1) {
            c4809b.f12297f = false;
            c4809b.f12299h = -1L;
            c4809b.f12298g = c4832c;
        } else {
            c4809b.f12297f = false;
            c4809b.f12299h = mo5479a;
            c4809b.f12298g = c4832c;
        }
        InterfaceC4800f mo5519n = interfaceC4852l.mo5519n("Content-Type");
        if (mo5519n != null) {
            c4809b.f12295c = mo5519n;
        }
        InterfaceC4800f mo5519n2 = interfaceC4852l.mo5519n("Content-Encoding");
        if (mo5519n2 != null) {
            c4809b.f12296e = mo5519n2;
        }
        interfaceC4852l.mo5511d(c4809b);
    }

    /* renamed from: b */
    public void m5482b() {
        Socket socket = this.f12308j.get();
        if (socket == null) {
            throw new C4790a();
        }
        C4844o c4844o = this.f12302c;
        if (!(c4844o.f12416g != null)) {
            c4844o.f12416g = socket.getInputStream();
        }
        C4845p c4845p = this.f12303e;
        if (c4845p.f12425f != null) {
            return;
        }
        c4845p.f12425f = socket.getOutputStream();
    }

    @Override // p476m.p477a.p485b.InterfaceC4807i, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        Socket andSet = this.f12308j.getAndSet(null);
        if (andSet != null) {
            try {
                C4844o c4844o = this.f12302c;
                c4844o.f12417h = 0;
                c4844o.f12418i = 0;
                this.f12303e.flush();
                try {
                    try {
                        andSet.shutdownOutput();
                    } catch (IOException unused) {
                    }
                    andSet.shutdownInput();
                } catch (IOException | UnsupportedOperationException unused2) {
                }
            } finally {
                andSet.close();
            }
        }
    }

    @Override // p476m.p477a.p485b.InterfaceC4901u
    public void flush() {
        m5482b();
        this.f12303e.flush();
    }

    @Override // p476m.p477a.p485b.InterfaceC4901u
    /* renamed from: g */
    public void mo5483g(InterfaceC4898r interfaceC4898r) {
        C2354n.m2470e1(interfaceC4898r, "HTTP response");
        m5482b();
        InterfaceC4846k interfaceC4846k = ((C4859g) interfaceC4898r).f12446f;
        if (interfaceC4846k == null) {
            return;
        }
        long mo5479a = this.f12307i.mo5479a(interfaceC4898r);
        C4845p c4845p = this.f12303e;
        OutputStream c4833d = mo5479a == -2 ? new C4833d(2048, c4845p) : mo5479a == -1 ? new C4843n(c4845p) : new C4835f(c4845p, mo5479a);
        interfaceC4846k.mo540a(c4833d);
        c4833d.close();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p476m.p477a.p485b.InterfaceC4901u
    /* renamed from: i */
    public void mo5484i(InterfaceC4898r interfaceC4898r) {
        C2354n.m2470e1(interfaceC4898r, "HTTP response");
        m5482b();
        AbstractC4831b<InterfaceC4898r> abstractC4831b = this.f12310l;
        Objects.requireNonNull(abstractC4831b);
        C2354n.m2470e1(interfaceC4898r, "HTTP message");
        C4838i c4838i = (C4838i) abstractC4831b;
        C4859g c4859g = (C4859g) interfaceC4898r;
        ((C4860h) c4838i.f12375c).m5533d(c4838i.f12374b, c4859g.mo5528h());
        c4838i.f12373a.mo5505c(c4838i.f12374b);
        InterfaceC4804h m5521p = ((AbstractC4853a) interfaceC4898r).m5521p();
        while (true) {
            C4862j c4862j = (C4862j) m5521p;
            if (!c4862j.hasNext()) {
                break;
            }
            abstractC4831b.f12373a.mo5505c(((C4860h) abstractC4831b.f12375c).m5532c(abstractC4831b.f12374b, c4862j.mo5478b()));
        }
        C4893b c4893b = abstractC4831b.f12374b;
        c4893b.f12498e = 0;
        abstractC4831b.f12373a.mo5505c(c4893b);
        if (c4859g.mo5528h().mo5476c() >= 200) {
            this.f12305g.f12321b++;
        }
    }

    @Override // p476m.p477a.p485b.InterfaceC4807i
    public boolean isOpen() {
        return this.f12308j.get() != null;
    }

    @Override // p476m.p477a.p485b.InterfaceC4807i
    public void shutdown() {
        Socket andSet = this.f12308j.getAndSet(null);
        if (andSet != null) {
            try {
                andSet.setSoLinger(true, 0);
            } catch (IOException unused) {
            } catch (Throwable th) {
                andSet.close();
                throw th;
            }
            andSet.close();
        }
    }

    public String toString() {
        Socket socket = this.f12308j.get();
        if (socket == null) {
            return "[Not bound]";
        }
        StringBuilder sb = new StringBuilder();
        SocketAddress remoteSocketAddress = socket.getRemoteSocketAddress();
        SocketAddress localSocketAddress = socket.getLocalSocketAddress();
        if (remoteSocketAddress != null && localSocketAddress != null) {
            C4894c.m5566a(sb, localSocketAddress);
            sb.append("<->");
            C4894c.m5566a(sb, remoteSocketAddress);
        }
        return sb.toString();
    }
}
