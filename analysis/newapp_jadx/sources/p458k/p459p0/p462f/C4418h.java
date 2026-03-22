package p458k.p459p0.p462f;

import java.io.IOException;
import java.lang.ref.Reference;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.AbstractC4485v;
import p458k.C4368a;
import p458k.C4375d0;
import p458k.C4395n0;
import p458k.C4487x;
import p458k.C4489z;
import p458k.EnumC4377e0;
import p458k.InterfaceC4369a0;
import p458k.InterfaceC4378f;
import p458k.InterfaceC4388k;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.C4410c;
import p458k.p459p0.p463g.InterfaceC4427d;
import p458k.p459p0.p464h.C4434a;
import p458k.p459p0.p465i.C4439e;
import p458k.p459p0.p465i.C4440f;
import p458k.p459p0.p465i.C4447m;
import p458k.p459p0.p465i.C4449o;
import p458k.p459p0.p465i.C4450p;
import p458k.p459p0.p465i.C4454t;
import p458k.p459p0.p465i.EnumC4436b;
import p458k.p459p0.p467k.C4463g;
import p458k.p459p0.p470m.C4477d;
import p474l.C4737a0;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;

/* renamed from: k.p0.f.h */
/* loaded from: classes3.dex */
public final class C4418h extends C4440f.c implements InterfaceC4388k {

    /* renamed from: b */
    public Socket f11676b;

    /* renamed from: c */
    public Socket f11677c;

    /* renamed from: d */
    public C4487x f11678d;

    /* renamed from: e */
    public EnumC4377e0 f11679e;

    /* renamed from: f */
    public C4440f f11680f;

    /* renamed from: g */
    public InterfaceC4746h f11681g;

    /* renamed from: h */
    public InterfaceC4745g f11682h;

    /* renamed from: i */
    public boolean f11683i;

    /* renamed from: j */
    public int f11684j;

    /* renamed from: k */
    public int f11685k;

    /* renamed from: l */
    public int f11686l;

    /* renamed from: m */
    public int f11687m;

    /* renamed from: n */
    @NotNull
    public final List<Reference<C4423m>> f11688n;

    /* renamed from: o */
    public long f11689o;

    /* renamed from: p */
    @NotNull
    public final C4419i f11690p;

    /* renamed from: q */
    public final C4395n0 f11691q;

    public C4418h(@NotNull C4419i connectionPool, @NotNull C4395n0 route) {
        Intrinsics.checkParameterIsNotNull(connectionPool, "connectionPool");
        Intrinsics.checkParameterIsNotNull(route, "route");
        this.f11690p = connectionPool;
        this.f11691q = route;
        this.f11687m = 1;
        this.f11688n = new ArrayList();
        this.f11689o = Long.MAX_VALUE;
    }

    @Override // p458k.p459p0.p465i.C4440f.c
    /* renamed from: a */
    public void mo5097a(@NotNull C4440f connection, @NotNull C4454t settings) {
        Intrinsics.checkParameterIsNotNull(connection, "connection");
        Intrinsics.checkParameterIsNotNull(settings, "settings");
        synchronized (this.f11690p) {
            this.f11687m = (settings.f11955a & 16) != 0 ? settings.f11956b[4] : Integer.MAX_VALUE;
            Unit unit = Unit.INSTANCE;
        }
    }

    @Override // p458k.p459p0.p465i.C4440f.c
    /* renamed from: b */
    public void mo5098b(@NotNull C4449o stream) {
        Intrinsics.checkParameterIsNotNull(stream, "stream");
        stream.m5193c(EnumC4436b.REFUSED_STREAM, null);
    }

    /* renamed from: c */
    public final void m5099c(int i2, int i3, InterfaceC4378f call, AbstractC4485v abstractC4485v) {
        Socket socket;
        int i4;
        C4395n0 c4395n0 = this.f11691q;
        Proxy proxy = c4395n0.f11529b;
        C4368a c4368a = c4395n0.f11528a;
        Proxy.Type type = proxy.type();
        if (type != null && ((i4 = C4415e.f11670a[type.ordinal()]) == 1 || i4 == 2)) {
            socket = c4368a.f11300e.createSocket();
            if (socket == null) {
                Intrinsics.throwNpe();
            }
        } else {
            socket = new Socket(proxy);
        }
        this.f11676b = socket;
        InetSocketAddress inetSocketAddress = this.f11691q.f11530c;
        Objects.requireNonNull(abstractC4485v);
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(inetSocketAddress, "inetSocketAddress");
        Intrinsics.checkParameterIsNotNull(proxy, "proxy");
        socket.setSoTimeout(i3);
        try {
            C4463g.a aVar = C4463g.f11988c;
            C4463g.f11986a.mo5238g(socket, this.f11691q.f11530c, i2);
            try {
                this.f11681g = C2354n.m2500o(C2354n.m2400I1(socket));
                this.f11682h = C2354n.m2497n(C2354n.m2388E1(socket));
            } catch (NullPointerException e2) {
                if (Intrinsics.areEqual(e2.getMessage(), "throw with null exception")) {
                    throw new IOException(e2);
                }
            }
        } catch (ConnectException e3) {
            StringBuilder m586H = C1499a.m586H("Failed to connect to ");
            m586H.append(this.f11691q.f11530c);
            ConnectException connectException = new ConnectException(m586H.toString());
            connectException.initCause(e3);
            throw connectException;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x0164, code lost:
    
        if (r3 == null) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0166, code lost:
    
        r5 = r19.f11676b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0168, code lost:
    
        if (r5 == null) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x016a, code lost:
    
        p458k.p459p0.C4401c.m5020e(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x016d, code lost:
    
        r5 = false;
        r19.f11676b = null;
        r19.f11682h = null;
        r19.f11681g = null;
        r6 = r19.f11691q;
        r8 = r6.f11530c;
        r6 = r6.f11529b;
        java.util.Objects.requireNonNull(r24);
        kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r23, "call");
        kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r8, "inetSocketAddress");
        kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r6, "proxy");
        r7 = r7 + 1;
        r6 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0199, code lost:
    
        return;
     */
    /* JADX WARN: Type inference failed for: r5v16 */
    /* JADX WARN: Type inference failed for: r5v19 */
    /* JADX WARN: Type inference failed for: r5v2, types: [k.d0, k.p0.f.h] */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m5100d(int r20, int r21, int r22, p458k.InterfaceC4378f r23, p458k.AbstractC4485v r24) {
        /*
            Method dump skipped, instructions count: 410
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p462f.C4418h.m5100d(int, int, int, k.f, k.v):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:73:0x01f8  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0201  */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m5101e(p458k.p459p0.p462f.C4412b r18, int r19, p458k.InterfaceC4378f r20, p458k.AbstractC4485v r21) {
        /*
            Method dump skipped, instructions count: 517
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p462f.C4418h.m5101e(k.p0.f.b, int, k.f, k.v):void");
    }

    /* renamed from: f */
    public final boolean m5102f() {
        return this.f11680f != null;
    }

    @NotNull
    /* renamed from: g */
    public final InterfaceC4427d m5103g(@NotNull C4375d0 client, @NotNull InterfaceC4369a0.a chain) {
        Intrinsics.checkParameterIsNotNull(client, "client");
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        Socket socket = this.f11677c;
        if (socket == null) {
            Intrinsics.throwNpe();
        }
        InterfaceC4746h interfaceC4746h = this.f11681g;
        if (interfaceC4746h == null) {
            Intrinsics.throwNpe();
        }
        InterfaceC4745g interfaceC4745g = this.f11682h;
        if (interfaceC4745g == null) {
            Intrinsics.throwNpe();
        }
        C4440f c4440f = this.f11680f;
        if (c4440f != null) {
            return new C4447m(client, this, chain, c4440f);
        }
        socket.setSoTimeout(chain.mo4941a());
        C4737a0 mo5044c = interfaceC4746h.mo5044c();
        long mo4941a = chain.mo4941a();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        mo5044c.mo5343g(mo4941a, timeUnit);
        interfaceC4745g.mo5151c().mo5343g(chain.mo4942b(), timeUnit);
        return new C4434a(client, this, interfaceC4746h, interfaceC4745g);
    }

    /* renamed from: h */
    public final void m5104h() {
        C4419i c4419i = this.f11690p;
        byte[] bArr = C4401c.f11556a;
        synchronized (c4419i) {
            this.f11683i = true;
            Unit unit = Unit.INSTANCE;
        }
    }

    @NotNull
    /* renamed from: i */
    public EnumC4377e0 m5105i() {
        EnumC4377e0 enumC4377e0 = this.f11679e;
        if (enumC4377e0 == null) {
            Intrinsics.throwNpe();
        }
        return enumC4377e0;
    }

    @NotNull
    /* renamed from: j */
    public Socket m5106j() {
        Socket socket = this.f11677c;
        if (socket == null) {
            Intrinsics.throwNpe();
        }
        return socket;
    }

    /* renamed from: k */
    public final void m5107k(int i2) {
        Socket socket = this.f11677c;
        if (socket == null) {
            Intrinsics.throwNpe();
        }
        InterfaceC4746h source = this.f11681g;
        if (source == null) {
            Intrinsics.throwNpe();
        }
        InterfaceC4745g sink = this.f11682h;
        if (sink == null) {
            Intrinsics.throwNpe();
        }
        socket.setSoTimeout(0);
        C4440f.b bVar = new C4440f.b(true, C4410c.f11626a);
        String peerName = this.f11691q.f11528a.f11296a.f12049g;
        Intrinsics.checkParameterIsNotNull(socket, "socket");
        Intrinsics.checkParameterIsNotNull(peerName, "peerName");
        Intrinsics.checkParameterIsNotNull(source, "source");
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        bVar.f11850a = socket;
        bVar.f11851b = bVar.f11857h ? C1499a.m637w("OkHttp ", peerName) : C1499a.m637w("MockWebServer ", peerName);
        bVar.f11852c = source;
        bVar.f11853d = sink;
        Intrinsics.checkParameterIsNotNull(this, "listener");
        bVar.f11854e = this;
        bVar.f11856g = i2;
        C4440f c4440f = new C4440f(bVar);
        this.f11680f = c4440f;
        C4440f c4440f2 = C4440f.f11819e;
        C4454t c4454t = C4440f.f11818c;
        this.f11687m = (c4454t.f11955a & 16) != 0 ? c4454t.f11956b[4] : Integer.MAX_VALUE;
        C4450p c4450p = c4440f.f11824E;
        synchronized (c4450p) {
            if (c4450p.f11943g) {
                throw new IOException("closed");
            }
            if (c4450p.f11946j) {
                Logger logger = C4450p.f11940c;
                if (logger.isLoggable(Level.FINE)) {
                    logger.fine(C4401c.m5024i(">> CONNECTION " + C4439e.f11813a.mo5401d(), new Object[0]));
                }
                c4450p.f11945i.mo5357H(C4439e.f11813a);
                c4450p.f11945i.flush();
            }
        }
        C4450p c4450p2 = c4440f.f11824E;
        C4454t settings = c4440f.f11845x;
        synchronized (c4450p2) {
            Intrinsics.checkParameterIsNotNull(settings, "settings");
            if (c4450p2.f11943g) {
                throw new IOException("closed");
            }
            c4450p2.m5209e(0, Integer.bitCount(settings.f11955a) * 6, 4, 0);
            int i3 = 0;
            while (i3 < 10) {
                if (((1 << i3) & settings.f11955a) != 0) {
                    c4450p2.f11945i.mo5383h(i3 != 4 ? i3 != 7 ? i3 : 4 : 3);
                    c4450p2.f11945i.mo5385j(settings.f11956b[i3]);
                }
                i3++;
            }
            c4450p2.f11945i.flush();
        }
        if (c4440f.f11845x.m5221a() != 65535) {
            c4440f.f11824E.m5214t(0, r0 - 65535);
        }
        new Thread(c4440f.f11825F, c4440f.f11830i).start();
    }

    /* renamed from: l */
    public final boolean m5108l(@NotNull C4489z url) {
        Intrinsics.checkParameterIsNotNull(url, "url");
        C4489z c4489z = this.f11691q.f11528a.f11296a;
        if (url.f12050h != c4489z.f12050h) {
            return false;
        }
        if (Intrinsics.areEqual(url.f12049g, c4489z.f12049g)) {
            return true;
        }
        C4487x c4487x = this.f11678d;
        if (c4487x == null) {
            return false;
        }
        C4477d c4477d = C4477d.f12010a;
        String str = url.f12049g;
        if (c4487x == null) {
            Intrinsics.throwNpe();
        }
        Certificate certificate = c4487x.m5273b().get(0);
        if (certificate != null) {
            return c4477d.m5259b(str, (X509Certificate) certificate);
        }
        throw new TypeCastException("null cannot be cast to non-null type java.security.cert.X509Certificate");
    }

    @NotNull
    public String toString() {
        Object obj;
        StringBuilder m586H = C1499a.m586H("Connection{");
        m586H.append(this.f11691q.f11528a.f11296a.f12049g);
        m586H.append(':');
        m586H.append(this.f11691q.f11528a.f11296a.f12050h);
        m586H.append(',');
        m586H.append(" proxy=");
        m586H.append(this.f11691q.f11529b);
        m586H.append(" hostAddress=");
        m586H.append(this.f11691q.f11530c);
        m586H.append(" cipherSuite=");
        C4487x c4487x = this.f11678d;
        if (c4487x == null || (obj = c4487x.f12036e) == null) {
            obj = "none";
        }
        m586H.append(obj);
        m586H.append(" protocol=");
        m586H.append(this.f11679e);
        m586H.append('}');
        return m586H.toString();
    }
}
