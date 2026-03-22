package p458k;

import java.net.ProxySelector;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import kotlin.TypeCastException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4485v;
import p458k.InterfaceC4378f;
import p458k.p459p0.C4399a;
import p458k.p459p0.C4401c;
import p458k.p459p0.p462f.C4423m;
import p458k.p459p0.p467k.C4463g;
import p458k.p459p0.p469l.C4473a;
import p458k.p459p0.p470m.AbstractC4476c;
import p458k.p459p0.p470m.C4477d;

/* renamed from: k.d0 */
/* loaded from: classes3.dex */
public class C4375d0 implements Cloneable, InterfaceC4378f.a {

    /* renamed from: A */
    @NotNull
    public final C4382h f11362A;

    /* renamed from: B */
    @Nullable
    public final AbstractC4476c f11363B;

    /* renamed from: C */
    public final int f11364C;

    /* renamed from: D */
    public final int f11365D;

    /* renamed from: E */
    public final int f11366E;

    /* renamed from: g */
    @NotNull
    public final C4482s f11367g;

    /* renamed from: h */
    @NotNull
    public final C4390l f11368h;

    /* renamed from: i */
    @NotNull
    public final List<InterfaceC4369a0> f11369i;

    /* renamed from: j */
    @NotNull
    public final List<InterfaceC4369a0> f11370j;

    /* renamed from: k */
    @NotNull
    public final AbstractC4485v.b f11371k;

    /* renamed from: l */
    public final boolean f11372l;

    /* renamed from: m */
    @NotNull
    public final InterfaceC4372c f11373m;

    /* renamed from: n */
    public final boolean f11374n;

    /* renamed from: o */
    public final boolean f11375o;

    /* renamed from: p */
    @NotNull
    public final InterfaceC4481r f11376p;

    /* renamed from: q */
    @Nullable
    public final C4374d f11377q;

    /* renamed from: r */
    @NotNull
    public final InterfaceC4484u f11378r;

    /* renamed from: s */
    @NotNull
    public final ProxySelector f11379s;

    /* renamed from: t */
    @NotNull
    public final InterfaceC4372c f11380t;

    /* renamed from: u */
    @NotNull
    public final SocketFactory f11381u;

    /* renamed from: v */
    public final SSLSocketFactory f11382v;

    /* renamed from: w */
    @Nullable
    public final X509TrustManager f11383w;

    /* renamed from: x */
    @NotNull
    public final List<C4392m> f11384x;

    /* renamed from: y */
    @NotNull
    public final List<EnumC4377e0> f11385y;

    /* renamed from: z */
    @NotNull
    public final HostnameVerifier f11386z;

    /* renamed from: f */
    public static final b f11361f = new b(null);

    /* renamed from: c */
    @NotNull
    public static final List<EnumC4377e0> f11359c = C4401c.m5027l(EnumC4377e0.HTTP_2, EnumC4377e0.HTTP_1_1);

    /* renamed from: e */
    @NotNull
    public static final List<C4392m> f11360e = C4401c.m5027l(C4392m.f11517c, C4392m.f11518d);

    /* renamed from: k.d0$a */
    public static final class a {

        /* renamed from: a */
        @NotNull
        public C4482s f11387a = new C4482s();

        /* renamed from: b */
        @NotNull
        public C4390l f11388b = new C4390l();

        /* renamed from: c */
        @NotNull
        public final List<InterfaceC4369a0> f11389c = new ArrayList();

        /* renamed from: d */
        @NotNull
        public final List<InterfaceC4369a0> f11390d = new ArrayList();

        /* renamed from: e */
        @NotNull
        public AbstractC4485v.b f11391e;

        /* renamed from: f */
        public boolean f11392f;

        /* renamed from: g */
        @NotNull
        public InterfaceC4372c f11393g;

        /* renamed from: h */
        public boolean f11394h;

        /* renamed from: i */
        public boolean f11395i;

        /* renamed from: j */
        @NotNull
        public InterfaceC4481r f11396j;

        /* renamed from: k */
        @Nullable
        public C4374d f11397k;

        /* renamed from: l */
        @NotNull
        public InterfaceC4484u f11398l;

        /* renamed from: m */
        @NotNull
        public InterfaceC4372c f11399m;

        /* renamed from: n */
        @NotNull
        public SocketFactory f11400n;

        /* renamed from: o */
        @NotNull
        public List<C4392m> f11401o;

        /* renamed from: p */
        @NotNull
        public List<? extends EnumC4377e0> f11402p;

        /* renamed from: q */
        @NotNull
        public HostnameVerifier f11403q;

        /* renamed from: r */
        @NotNull
        public C4382h f11404r;

        /* renamed from: s */
        public int f11405s;

        /* renamed from: t */
        public int f11406t;

        /* renamed from: u */
        public int f11407u;

        public a() {
            AbstractC4485v asFactory = AbstractC4485v.f12025a;
            byte[] bArr = C4401c.f11556a;
            Intrinsics.checkParameterIsNotNull(asFactory, "$this$asFactory");
            this.f11391e = new C4399a(asFactory);
            this.f11392f = true;
            InterfaceC4372c interfaceC4372c = InterfaceC4372c.f11313a;
            this.f11393g = interfaceC4372c;
            this.f11394h = true;
            this.f11395i = true;
            this.f11396j = InterfaceC4481r.f12019a;
            this.f11398l = InterfaceC4484u.f12024a;
            this.f11399m = interfaceC4372c;
            SocketFactory socketFactory = SocketFactory.getDefault();
            Intrinsics.checkExpressionValueIsNotNull(socketFactory, "SocketFactory.getDefault()");
            this.f11400n = socketFactory;
            b bVar = C4375d0.f11361f;
            this.f11401o = C4375d0.f11360e;
            this.f11402p = C4375d0.f11359c;
            this.f11403q = C4477d.f12010a;
            this.f11404r = C4382h.f11450a;
            this.f11405s = 10000;
            this.f11406t = 10000;
            this.f11407u = 10000;
        }

        @NotNull
        /* renamed from: a */
        public final a m4956a(@NotNull InterfaceC4369a0 interceptor) {
            Intrinsics.checkParameterIsNotNull(interceptor, "interceptor");
            this.f11389c.add(interceptor);
            return this;
        }

        @NotNull
        /* renamed from: b */
        public final a m4957b(long j2, @NotNull TimeUnit unit) {
            Intrinsics.checkParameterIsNotNull(unit, "unit");
            this.f11405s = C4401c.m5017b("timeout", j2, unit);
            return this;
        }

        @NotNull
        /* renamed from: c */
        public final a m4958c(long j2, @NotNull TimeUnit unit) {
            Intrinsics.checkParameterIsNotNull(unit, "unit");
            this.f11406t = C4401c.m5017b("timeout", j2, unit);
            return this;
        }

        @NotNull
        /* renamed from: d */
        public final a m4959d(long j2, @NotNull TimeUnit unit) {
            Intrinsics.checkParameterIsNotNull(unit, "unit");
            this.f11407u = C4401c.m5017b("timeout", j2, unit);
            return this;
        }
    }

    /* renamed from: k.d0$b */
    public static final class b {
        public b(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    public C4375d0(@NotNull a builder) {
        boolean z;
        Intrinsics.checkParameterIsNotNull(builder, "builder");
        this.f11367g = builder.f11387a;
        this.f11368h = builder.f11388b;
        this.f11369i = C4401c.m5038w(builder.f11389c);
        this.f11370j = C4401c.m5038w(builder.f11390d);
        this.f11371k = builder.f11391e;
        this.f11372l = builder.f11392f;
        this.f11373m = builder.f11393g;
        this.f11374n = builder.f11394h;
        this.f11375o = builder.f11395i;
        this.f11376p = builder.f11396j;
        this.f11377q = builder.f11397k;
        this.f11378r = builder.f11398l;
        ProxySelector proxySelector = ProxySelector.getDefault();
        this.f11379s = proxySelector == null ? C4473a.f12007a : proxySelector;
        this.f11380t = builder.f11399m;
        this.f11381u = builder.f11400n;
        List<C4392m> list = builder.f11401o;
        this.f11384x = list;
        this.f11385y = builder.f11402p;
        this.f11386z = builder.f11403q;
        this.f11364C = builder.f11405s;
        this.f11365D = builder.f11406t;
        this.f11366E = builder.f11407u;
        if (!(list instanceof Collection) || !list.isEmpty()) {
            Iterator<T> it = list.iterator();
            while (it.hasNext()) {
                if (((C4392m) it.next()).f11519e) {
                    z = false;
                    break;
                }
            }
        }
        z = true;
        if (z) {
            this.f11382v = null;
            this.f11363B = null;
            this.f11383w = null;
        } else {
            C4463g.a aVar = C4463g.f11988c;
            X509TrustManager trustManager = C4463g.f11986a.mo5246o();
            this.f11383w = trustManager;
            C4463g.f11986a.mo5244f(trustManager);
            if (trustManager == null) {
                Intrinsics.throwNpe();
            }
            try {
                SSLContext mo5245n = C4463g.f11986a.mo5245n();
                mo5245n.init(null, new TrustManager[]{trustManager}, null);
                SSLSocketFactory socketFactory = mo5245n.getSocketFactory();
                Intrinsics.checkExpressionValueIsNotNull(socketFactory, "sslContext.socketFactory");
                this.f11382v = socketFactory;
                if (trustManager == null) {
                    Intrinsics.throwNpe();
                }
                Intrinsics.checkParameterIsNotNull(trustManager, "trustManager");
                this.f11363B = C4463g.f11986a.mo5232b(trustManager);
            } catch (GeneralSecurityException e2) {
                throw new AssertionError("No System TLS", e2);
            }
        }
        if (this.f11382v != null) {
            C4463g.a aVar2 = C4463g.f11988c;
            C4463g.f11986a.mo5243d(this.f11382v);
        }
        C4382h c4382h = builder.f11404r;
        AbstractC4476c abstractC4476c = this.f11363B;
        this.f11362A = Intrinsics.areEqual(c4382h.f11453d, abstractC4476c) ? c4382h : new C4382h(c4382h.f11452c, abstractC4476c);
        if (this.f11369i == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>");
        }
        if (!(!r7.contains(null))) {
            StringBuilder m586H = C1499a.m586H("Null interceptor: ");
            m586H.append(this.f11369i);
            throw new IllegalStateException(m586H.toString().toString());
        }
        if (this.f11370j == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>");
        }
        if (!r7.contains(null)) {
            return;
        }
        StringBuilder m586H2 = C1499a.m586H("Null network interceptor: ");
        m586H2.append(this.f11370j);
        throw new IllegalStateException(m586H2.toString().toString());
    }

    @Override // p458k.InterfaceC4378f.a
    @NotNull
    /* renamed from: a */
    public InterfaceC4378f mo4955a(@NotNull C4381g0 originalRequest) {
        Intrinsics.checkParameterIsNotNull(originalRequest, "request");
        Intrinsics.checkParameterIsNotNull(this, "client");
        Intrinsics.checkParameterIsNotNull(originalRequest, "originalRequest");
        C4379f0 c4379f0 = new C4379f0(this, originalRequest, false, null);
        c4379f0.f11431c = new C4423m(this, c4379f0);
        return c4379f0;
    }

    @NotNull
    public Object clone() {
        return super.clone();
    }

    public C4375d0() {
        this(new a());
    }
}
