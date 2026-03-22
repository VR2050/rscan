package p458k.p459p0.p464h;

import java.io.EOFException;
import java.io.IOException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Socket;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4368a;
import p458k.C4375d0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4395n0;
import p458k.C4488y;
import p458k.C4489z;
import p458k.InterfaceC4481r;
import p458k.p459p0.C4401c;
import p458k.p459p0.p462f.C4418h;
import p458k.p459p0.p463g.C4428e;
import p458k.p459p0.p463g.C4433j;
import p458k.p459p0.p463g.InterfaceC4427d;
import p474l.C4737a0;
import p474l.C4744f;
import p474l.C4750l;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;

/* renamed from: k.p0.h.a */
/* loaded from: classes3.dex */
public final class C4434a implements InterfaceC4427d {

    /* renamed from: a */
    public int f11751a;

    /* renamed from: b */
    public long f11752b;

    /* renamed from: c */
    public C4488y f11753c;

    /* renamed from: d */
    public final C4375d0 f11754d;

    /* renamed from: e */
    public final C4418h f11755e;

    /* renamed from: f */
    public final InterfaceC4746h f11756f;

    /* renamed from: g */
    public final InterfaceC4745g f11757g;

    /* renamed from: k.p0.h.a$a */
    public abstract class a implements InterfaceC4764z {

        /* renamed from: c */
        @NotNull
        public final C4750l f11758c;

        /* renamed from: e */
        public boolean f11759e;

        public a() {
            this.f11758c = new C4750l(C4434a.this.f11756f.mo5044c());
        }

        @Override // p474l.InterfaceC4764z
        /* renamed from: J */
        public long mo4924J(@NotNull C4744f sink, long j2) {
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            try {
                return C4434a.this.f11756f.mo4924J(sink, j2);
            } catch (IOException e2) {
                C4418h c4418h = C4434a.this.f11755e;
                if (c4418h == null) {
                    Intrinsics.throwNpe();
                }
                c4418h.m5104h();
                m5150b();
                throw e2;
            }
        }

        /* renamed from: b */
        public final void m5150b() {
            C4434a c4434a = C4434a.this;
            int i2 = c4434a.f11751a;
            if (i2 == 6) {
                return;
            }
            if (i2 == 5) {
                C4434a.m5145i(c4434a, this.f11758c);
                C4434a.this.f11751a = 6;
            } else {
                StringBuilder m586H = C1499a.m586H("state: ");
                m586H.append(C4434a.this.f11751a);
                throw new IllegalStateException(m586H.toString());
            }
        }

        @Override // p474l.InterfaceC4764z
        @NotNull
        /* renamed from: c */
        public C4737a0 mo5044c() {
            return this.f11758c;
        }
    }

    /* renamed from: k.p0.h.a$b */
    public final class b implements InterfaceC4762x {

        /* renamed from: c */
        public final C4750l f11761c;

        /* renamed from: e */
        public boolean f11762e;

        public b() {
            this.f11761c = new C4750l(C4434a.this.f11757g.mo5151c());
        }

        @Override // p474l.InterfaceC4762x
        @NotNull
        /* renamed from: c */
        public C4737a0 mo5151c() {
            return this.f11761c;
        }

        @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
        public synchronized void close() {
            if (this.f11762e) {
                return;
            }
            this.f11762e = true;
            C4434a.this.f11757g.mo5393u("0\r\n\r\n");
            C4434a.m5145i(C4434a.this, this.f11761c);
            C4434a.this.f11751a = 3;
        }

        @Override // p474l.InterfaceC4762x, java.io.Flushable
        public synchronized void flush() {
            if (this.f11762e) {
                return;
            }
            C4434a.this.f11757g.flush();
        }

        @Override // p474l.InterfaceC4762x
        /* renamed from: x */
        public void mo4923x(@NotNull C4744f source, long j2) {
            Intrinsics.checkParameterIsNotNull(source, "source");
            if (!(!this.f11762e)) {
                throw new IllegalStateException("closed".toString());
            }
            if (j2 == 0) {
                return;
            }
            C4434a.this.f11757g.mo5397z(j2);
            C4434a.this.f11757g.mo5393u("\r\n");
            C4434a.this.f11757g.mo4923x(source, j2);
            C4434a.this.f11757g.mo5393u("\r\n");
        }
    }

    /* renamed from: k.p0.h.a$c */
    public final class c extends a {

        /* renamed from: g */
        public long f11764g;

        /* renamed from: h */
        public boolean f11765h;

        /* renamed from: i */
        public final C4489z f11766i;

        /* renamed from: j */
        public final /* synthetic */ C4434a f11767j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public c(@NotNull C4434a c4434a, C4489z url) {
            super();
            Intrinsics.checkParameterIsNotNull(url, "url");
            this.f11767j = c4434a;
            this.f11766i = url;
            this.f11764g = -1L;
            this.f11765h = true;
        }

        @Override // p458k.p459p0.p464h.C4434a.a, p474l.InterfaceC4764z
        /* renamed from: J */
        public long mo4924J(@NotNull C4744f sink, long j2) {
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            boolean z = true;
            if (!(j2 >= 0)) {
                throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
            }
            if (!(!this.f11759e)) {
                throw new IllegalStateException("closed".toString());
            }
            if (!this.f11765h) {
                return -1L;
            }
            long j3 = this.f11764g;
            if (j3 == 0 || j3 == -1) {
                if (j3 != -1) {
                    this.f11767j.f11756f.mo5351B();
                }
                try {
                    this.f11764g = this.f11767j.f11756f.mo5363Q();
                    String mo5351B = this.f11767j.f11756f.mo5351B();
                    if (mo5351B == null) {
                        throw new TypeCastException("null cannot be cast to non-null type kotlin.CharSequence");
                    }
                    String obj = StringsKt__StringsKt.trim((CharSequence) mo5351B).toString();
                    if (this.f11764g >= 0) {
                        if (obj.length() <= 0) {
                            z = false;
                        }
                        if (!z || StringsKt__StringsJVMKt.startsWith$default(obj, ";", false, 2, null)) {
                            if (this.f11764g == 0) {
                                this.f11765h = false;
                                C4434a c4434a = this.f11767j;
                                c4434a.f11753c = c4434a.m5148l();
                                C4375d0 c4375d0 = this.f11767j.f11754d;
                                if (c4375d0 == null) {
                                    Intrinsics.throwNpe();
                                }
                                InterfaceC4481r interfaceC4481r = c4375d0.f11376p;
                                C4489z c4489z = this.f11766i;
                                C4488y c4488y = this.f11767j.f11753c;
                                if (c4488y == null) {
                                    Intrinsics.throwNpe();
                                }
                                C4428e.m5136b(interfaceC4481r, c4489z, c4488y);
                                m5150b();
                            }
                            if (!this.f11765h) {
                                return -1L;
                            }
                        }
                    }
                    throw new ProtocolException("expected chunk size and optional extensions but was \"" + this.f11764g + obj + Typography.quote);
                } catch (NumberFormatException e2) {
                    throw new ProtocolException(e2.getMessage());
                }
            }
            long mo4924J = super.mo4924J(sink, Math.min(j2, this.f11764g));
            if (mo4924J != -1) {
                this.f11764g -= mo4924J;
                return mo4924J;
            }
            C4418h c4418h = this.f11767j.f11755e;
            if (c4418h == null) {
                Intrinsics.throwNpe();
            }
            c4418h.m5104h();
            ProtocolException protocolException = new ProtocolException("unexpected end of stream");
            m5150b();
            throw protocolException;
        }

        @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f11759e) {
                return;
            }
            if (this.f11765h && !C4401c.m5023h(this, 100, TimeUnit.MILLISECONDS)) {
                C4418h c4418h = this.f11767j.f11755e;
                if (c4418h == null) {
                    Intrinsics.throwNpe();
                }
                c4418h.m5104h();
                m5150b();
            }
            this.f11759e = true;
        }
    }

    /* renamed from: k.p0.h.a$d */
    public final class d extends a {

        /* renamed from: g */
        public long f11768g;

        public d(long j2) {
            super();
            this.f11768g = j2;
            if (j2 == 0) {
                m5150b();
            }
        }

        @Override // p458k.p459p0.p464h.C4434a.a, p474l.InterfaceC4764z
        /* renamed from: J */
        public long mo4924J(@NotNull C4744f sink, long j2) {
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            if (!(j2 >= 0)) {
                throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
            }
            if (!(!this.f11759e)) {
                throw new IllegalStateException("closed".toString());
            }
            long j3 = this.f11768g;
            if (j3 == 0) {
                return -1L;
            }
            long mo4924J = super.mo4924J(sink, Math.min(j3, j2));
            if (mo4924J != -1) {
                long j4 = this.f11768g - mo4924J;
                this.f11768g = j4;
                if (j4 == 0) {
                    m5150b();
                }
                return mo4924J;
            }
            C4418h c4418h = C4434a.this.f11755e;
            if (c4418h == null) {
                Intrinsics.throwNpe();
            }
            c4418h.m5104h();
            ProtocolException protocolException = new ProtocolException("unexpected end of stream");
            m5150b();
            throw protocolException;
        }

        @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f11759e) {
                return;
            }
            if (this.f11768g != 0 && !C4401c.m5023h(this, 100, TimeUnit.MILLISECONDS)) {
                C4418h c4418h = C4434a.this.f11755e;
                if (c4418h == null) {
                    Intrinsics.throwNpe();
                }
                c4418h.m5104h();
                m5150b();
            }
            this.f11759e = true;
        }
    }

    /* renamed from: k.p0.h.a$e */
    public final class e implements InterfaceC4762x {

        /* renamed from: c */
        public final C4750l f11770c;

        /* renamed from: e */
        public boolean f11771e;

        public e() {
            this.f11770c = new C4750l(C4434a.this.f11757g.mo5151c());
        }

        @Override // p474l.InterfaceC4762x
        @NotNull
        /* renamed from: c */
        public C4737a0 mo5151c() {
            return this.f11770c;
        }

        @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f11771e) {
                return;
            }
            this.f11771e = true;
            C4434a.m5145i(C4434a.this, this.f11770c);
            C4434a.this.f11751a = 3;
        }

        @Override // p474l.InterfaceC4762x, java.io.Flushable
        public void flush() {
            if (this.f11771e) {
                return;
            }
            C4434a.this.f11757g.flush();
        }

        @Override // p474l.InterfaceC4762x
        /* renamed from: x */
        public void mo4923x(@NotNull C4744f source, long j2) {
            Intrinsics.checkParameterIsNotNull(source, "source");
            if (!(!this.f11771e)) {
                throw new IllegalStateException("closed".toString());
            }
            C4401c.m5018c(source.f12133e, 0L, j2);
            C4434a.this.f11757g.mo4923x(source, j2);
        }
    }

    /* renamed from: k.p0.h.a$f */
    public final class f extends a {

        /* renamed from: g */
        public boolean f11773g;

        public f(C4434a c4434a) {
            super();
        }

        @Override // p458k.p459p0.p464h.C4434a.a, p474l.InterfaceC4764z
        /* renamed from: J */
        public long mo4924J(@NotNull C4744f sink, long j2) {
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            if (!(j2 >= 0)) {
                throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
            }
            if (!(!this.f11759e)) {
                throw new IllegalStateException("closed".toString());
            }
            if (this.f11773g) {
                return -1L;
            }
            long mo4924J = super.mo4924J(sink, j2);
            if (mo4924J != -1) {
                return mo4924J;
            }
            this.f11773g = true;
            m5150b();
            return -1L;
        }

        @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f11759e) {
                return;
            }
            if (!this.f11773g) {
                m5150b();
            }
            this.f11759e = true;
        }
    }

    public C4434a(@Nullable C4375d0 c4375d0, @Nullable C4418h c4418h, @NotNull InterfaceC4746h source, @NotNull InterfaceC4745g sink) {
        Intrinsics.checkParameterIsNotNull(source, "source");
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        this.f11754d = c4375d0;
        this.f11755e = c4418h;
        this.f11756f = source;
        this.f11757g = sink;
        this.f11752b = 262144;
    }

    /* renamed from: i */
    public static final void m5145i(C4434a c4434a, C4750l c4750l) {
        Objects.requireNonNull(c4434a);
        C4737a0 c4737a0 = c4750l.f12142e;
        C4737a0 delegate = C4737a0.f12115a;
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        c4750l.f12142e = delegate;
        c4737a0.mo5337a();
        c4737a0.mo5338b();
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: a */
    public void mo5127a() {
        this.f11757g.flush();
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: b */
    public void mo5128b(@NotNull C4381g0 request) {
        Intrinsics.checkParameterIsNotNull(request, "request");
        C4418h c4418h = this.f11755e;
        if (c4418h == null) {
            Intrinsics.throwNpe();
        }
        Proxy.Type proxyType = c4418h.f11691q.f11529b.type();
        Intrinsics.checkExpressionValueIsNotNull(proxyType, "realConnection!!.route().proxy.type()");
        Intrinsics.checkParameterIsNotNull(request, "request");
        Intrinsics.checkParameterIsNotNull(proxyType, "proxyType");
        StringBuilder sb = new StringBuilder();
        sb.append(request.f11441c);
        sb.append(' ');
        C4489z url = request.f11440b;
        if (!url.f12045c && proxyType == Proxy.Type.HTTP) {
            sb.append(url);
        } else {
            Intrinsics.checkParameterIsNotNull(url, "url");
            String m5292b = url.m5292b();
            String m5294d = url.m5294d();
            if (m5294d != null) {
                m5292b = m5292b + '?' + m5294d;
            }
            sb.append(m5292b);
        }
        sb.append(" HTTP/1.1");
        String sb2 = sb.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb2, "StringBuilder().apply(builderAction).toString()");
        m5149m(request.f11442d, sb2);
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @NotNull
    /* renamed from: c */
    public InterfaceC4764z mo5129c(@NotNull C4389k0 response) {
        Intrinsics.checkParameterIsNotNull(response, "response");
        if (!C4428e.m5135a(response)) {
            return m5146j(0L);
        }
        if (StringsKt__StringsJVMKt.equals("chunked", C4389k0.m4987d(response, "Transfer-Encoding", null, 2), true)) {
            C4489z c4489z = response.f11485e.f11440b;
            if (this.f11751a == 4) {
                this.f11751a = 5;
                return new c(this, c4489z);
            }
            StringBuilder m586H = C1499a.m586H("state: ");
            m586H.append(this.f11751a);
            throw new IllegalStateException(m586H.toString().toString());
        }
        long m5026k = C4401c.m5026k(response);
        if (m5026k != -1) {
            return m5146j(m5026k);
        }
        if (!(this.f11751a == 4)) {
            StringBuilder m586H2 = C1499a.m586H("state: ");
            m586H2.append(this.f11751a);
            throw new IllegalStateException(m586H2.toString().toString());
        }
        this.f11751a = 5;
        C4418h c4418h = this.f11755e;
        if (c4418h == null) {
            Intrinsics.throwNpe();
        }
        c4418h.m5104h();
        return new f(this);
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    public void cancel() {
        Socket socket;
        C4418h c4418h = this.f11755e;
        if (c4418h == null || (socket = c4418h.f11676b) == null) {
            return;
        }
        C4401c.m5020e(socket);
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @Nullable
    /* renamed from: d */
    public C4389k0.a mo5130d(boolean z) {
        String str;
        C4395n0 c4395n0;
        C4368a c4368a;
        C4489z c4489z;
        int i2 = this.f11751a;
        boolean z2 = true;
        if (i2 != 1 && i2 != 3) {
            z2 = false;
        }
        if (!z2) {
            StringBuilder m586H = C1499a.m586H("state: ");
            m586H.append(this.f11751a);
            throw new IllegalStateException(m586H.toString().toString());
        }
        try {
            C4433j m5144a = C4433j.m5144a(m5147k());
            C4389k0.a aVar = new C4389k0.a();
            aVar.m4996g(m5144a.f11748a);
            aVar.f11500c = m5144a.f11749b;
            aVar.m4995f(m5144a.f11750c);
            aVar.m4994e(m5148l());
            if (z && m5144a.f11749b == 100) {
                return null;
            }
            if (m5144a.f11749b == 100) {
                this.f11751a = 3;
                return aVar;
            }
            this.f11751a = 4;
            return aVar;
        } catch (EOFException e2) {
            C4418h c4418h = this.f11755e;
            if (c4418h == null || (c4395n0 = c4418h.f11691q) == null || (c4368a = c4395n0.f11528a) == null || (c4489z = c4368a.f11296a) == null || (str = c4489z.m5297g()) == null) {
                str = "unknown";
            }
            throw new IOException(C1499a.m637w("unexpected end of stream on ", str), e2);
        }
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @Nullable
    /* renamed from: e */
    public C4418h mo5131e() {
        return this.f11755e;
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: f */
    public void mo5132f() {
        this.f11757g.flush();
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: g */
    public long mo5133g(@NotNull C4389k0 response) {
        Intrinsics.checkParameterIsNotNull(response, "response");
        if (!C4428e.m5135a(response)) {
            return 0L;
        }
        if (StringsKt__StringsJVMKt.equals("chunked", C4389k0.m4987d(response, "Transfer-Encoding", null, 2), true)) {
            return -1L;
        }
        return C4401c.m5026k(response);
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @NotNull
    /* renamed from: h */
    public InterfaceC4762x mo5134h(@NotNull C4381g0 request, long j2) {
        Intrinsics.checkParameterIsNotNull(request, "request");
        if (StringsKt__StringsJVMKt.equals("chunked", request.m4970b("Transfer-Encoding"), true)) {
            if (this.f11751a == 1) {
                this.f11751a = 2;
                return new b();
            }
            StringBuilder m586H = C1499a.m586H("state: ");
            m586H.append(this.f11751a);
            throw new IllegalStateException(m586H.toString().toString());
        }
        if (j2 == -1) {
            throw new IllegalStateException("Cannot stream a request body without chunked encoding or a known content length!");
        }
        if (this.f11751a == 1) {
            this.f11751a = 2;
            return new e();
        }
        StringBuilder m586H2 = C1499a.m586H("state: ");
        m586H2.append(this.f11751a);
        throw new IllegalStateException(m586H2.toString().toString());
    }

    /* renamed from: j */
    public final InterfaceC4764z m5146j(long j2) {
        if (this.f11751a == 4) {
            this.f11751a = 5;
            return new d(j2);
        }
        StringBuilder m586H = C1499a.m586H("state: ");
        m586H.append(this.f11751a);
        throw new IllegalStateException(m586H.toString().toString());
    }

    /* renamed from: k */
    public final String m5147k() {
        String mo5390r = this.f11756f.mo5390r(this.f11752b);
        this.f11752b -= mo5390r.length();
        return mo5390r;
    }

    /* renamed from: l */
    public final C4488y m5148l() {
        C4488y.a aVar = new C4488y.a();
        String m5147k = m5147k();
        while (true) {
            if (!(m5147k.length() > 0)) {
                return aVar.m5285d();
            }
            aVar.m5283b(m5147k);
            m5147k = m5147k();
        }
    }

    /* renamed from: m */
    public final void m5149m(@NotNull C4488y headers, @NotNull String requestLine) {
        Intrinsics.checkParameterIsNotNull(headers, "headers");
        Intrinsics.checkParameterIsNotNull(requestLine, "requestLine");
        if (!(this.f11751a == 0)) {
            StringBuilder m586H = C1499a.m586H("state: ");
            m586H.append(this.f11751a);
            throw new IllegalStateException(m586H.toString().toString());
        }
        this.f11757g.mo5393u(requestLine).mo5393u("\r\n");
        int size = headers.size();
        for (int i2 = 0; i2 < size; i2++) {
            this.f11757g.mo5393u(headers.m5278b(i2)).mo5393u(": ").mo5393u(headers.m5280d(i2)).mo5393u("\r\n");
        }
        this.f11757g.mo5393u("\r\n");
        this.f11751a = 1;
    }
}
