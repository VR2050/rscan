package p458k.p459p0.p465i;

import java.io.IOException;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.C4375d0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4488y;
import p458k.C4489z;
import p458k.EnumC4377e0;
import p458k.InterfaceC4369a0;
import p458k.p459p0.C4401c;
import p458k.p459p0.p462f.C4418h;
import p458k.p459p0.p463g.C4428e;
import p458k.p459p0.p463g.C4433j;
import p458k.p459p0.p463g.InterfaceC4427d;
import p458k.p459p0.p465i.C4449o;
import p474l.C4747i;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;

/* renamed from: k.p0.i.m */
/* loaded from: classes3.dex */
public final class C4447m implements InterfaceC4427d {

    /* renamed from: a */
    public static final List<String> f11895a = C4401c.m5027l("connection", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "encoding", "upgrade", ":method", ":path", ":scheme", ":authority");

    /* renamed from: b */
    public static final List<String> f11896b = C4401c.m5027l("connection", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "encoding", "upgrade");

    /* renamed from: c */
    public volatile C4449o f11897c;

    /* renamed from: d */
    public final EnumC4377e0 f11898d;

    /* renamed from: e */
    public volatile boolean f11899e;

    /* renamed from: f */
    public final C4418h f11900f;

    /* renamed from: g */
    public final InterfaceC4369a0.a f11901g;

    /* renamed from: h */
    public final C4440f f11902h;

    public C4447m(@NotNull C4375d0 client, @NotNull C4418h realConnection, @NotNull InterfaceC4369a0.a chain, @NotNull C4440f connection) {
        Intrinsics.checkParameterIsNotNull(client, "client");
        Intrinsics.checkParameterIsNotNull(realConnection, "realConnection");
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        Intrinsics.checkParameterIsNotNull(connection, "connection");
        this.f11900f = realConnection;
        this.f11901g = chain;
        this.f11902h = connection;
        List<EnumC4377e0> list = client.f11385y;
        EnumC4377e0 enumC4377e0 = EnumC4377e0.H2_PRIOR_KNOWLEDGE;
        this.f11898d = list.contains(enumC4377e0) ? enumC4377e0 : EnumC4377e0.HTTP_2;
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: a */
    public void mo5127a() {
        C4449o c4449o = this.f11897c;
        if (c4449o == null) {
            Intrinsics.throwNpe();
        }
        ((C4449o.a) c4449o.m5197g()).close();
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: b */
    public void mo5128b(@NotNull C4381g0 request) {
        int i2;
        C4449o c4449o;
        boolean z;
        Intrinsics.checkParameterIsNotNull(request, "request");
        if (this.f11897c != null) {
            return;
        }
        boolean z2 = request.f11443e != null;
        Intrinsics.checkParameterIsNotNull(request, "request");
        C4488y c4488y = request.f11442d;
        ArrayList requestHeaders = new ArrayList(c4488y.size() + 4);
        requestHeaders.add(new C4437c(C4437c.f11785c, request.f11441c));
        C4747i c4747i = C4437c.f11786d;
        C4489z url = request.f11440b;
        Intrinsics.checkParameterIsNotNull(url, "url");
        String m5292b = url.m5292b();
        String m5294d = url.m5294d();
        if (m5294d != null) {
            m5292b = m5292b + '?' + m5294d;
        }
        requestHeaders.add(new C4437c(c4747i, m5292b));
        String m4970b = request.m4970b("Host");
        if (m4970b != null) {
            requestHeaders.add(new C4437c(C4437c.f11788f, m4970b));
        }
        requestHeaders.add(new C4437c(C4437c.f11787e, request.f11440b.f12046d));
        int size = c4488y.size();
        for (int i3 = 0; i3 < size; i3++) {
            String m5278b = c4488y.m5278b(i3);
            Locale locale = Locale.US;
            Intrinsics.checkExpressionValueIsNotNull(locale, "Locale.US");
            if (m5278b == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            String lowerCase = m5278b.toLowerCase(locale);
            Intrinsics.checkExpressionValueIsNotNull(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
            if (!f11895a.contains(lowerCase) || (Intrinsics.areEqual(lowerCase, "te") && Intrinsics.areEqual(c4488y.m5280d(i3), "trailers"))) {
                requestHeaders.add(new C4437c(lowerCase, c4488y.m5280d(i3)));
            }
        }
        C4440f c4440f = this.f11902h;
        Objects.requireNonNull(c4440f);
        Intrinsics.checkParameterIsNotNull(requestHeaders, "requestHeaders");
        boolean z3 = !z2;
        synchronized (c4440f.f11824E) {
            synchronized (c4440f) {
                if (c4440f.f11832k > 1073741823) {
                    c4440f.m5172o(EnumC4436b.REFUSED_STREAM);
                }
                if (c4440f.f11833l) {
                    throw new C4435a();
                }
                i2 = c4440f.f11832k;
                c4440f.f11832k = i2 + 2;
                c4449o = new C4449o(i2, c4440f, z3, false, null);
                z = !z2 || c4440f.f11821B >= c4440f.f11822C || c4449o.f11917c >= c4449o.f11918d;
                if (c4449o.m5199i()) {
                    c4440f.f11829h.put(Integer.valueOf(i2), c4449o);
                }
                Unit unit = Unit.INSTANCE;
            }
            c4440f.f11824E.m5211o(z3, i2, requestHeaders);
        }
        if (z) {
            c4440f.f11824E.flush();
        }
        this.f11897c = c4449o;
        if (this.f11899e) {
            C4449o c4449o2 = this.f11897c;
            if (c4449o2 == null) {
                Intrinsics.throwNpe();
            }
            c4449o2.m5195e(EnumC4436b.CANCEL);
            throw new IOException("Canceled");
        }
        C4449o c4449o3 = this.f11897c;
        if (c4449o3 == null) {
            Intrinsics.throwNpe();
        }
        C4449o.c cVar = c4449o3.f11923i;
        long mo4941a = this.f11901g.mo4941a();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        cVar.mo5343g(mo4941a, timeUnit);
        C4449o c4449o4 = this.f11897c;
        if (c4449o4 == null) {
            Intrinsics.throwNpe();
        }
        c4449o4.f11924j.mo5343g(this.f11901g.mo4942b(), timeUnit);
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @NotNull
    /* renamed from: c */
    public InterfaceC4764z mo5129c(@NotNull C4389k0 response) {
        Intrinsics.checkParameterIsNotNull(response, "response");
        C4449o c4449o = this.f11897c;
        if (c4449o == null) {
            Intrinsics.throwNpe();
        }
        return c4449o.f11921g;
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    public void cancel() {
        this.f11899e = true;
        C4449o c4449o = this.f11897c;
        if (c4449o != null) {
            c4449o.m5195e(EnumC4436b.CANCEL);
        }
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @Nullable
    /* renamed from: d */
    public C4389k0.a mo5130d(boolean z) {
        C4488y headerBlock;
        C4449o c4449o = this.f11897c;
        if (c4449o == null) {
            Intrinsics.throwNpe();
        }
        synchronized (c4449o) {
            c4449o.f11923i.m5344h();
            while (c4449o.f11919e.isEmpty() && c4449o.f11925k == null) {
                try {
                    c4449o.m5202l();
                } catch (Throwable th) {
                    c4449o.f11923i.m5206l();
                    throw th;
                }
            }
            c4449o.f11923i.m5206l();
            if (!(!c4449o.f11919e.isEmpty())) {
                IOException iOException = c4449o.f11926l;
                if (iOException != null) {
                    throw iOException;
                }
                EnumC4436b enumC4436b = c4449o.f11925k;
                if (enumC4436b == null) {
                    Intrinsics.throwNpe();
                }
                throw new C4455u(enumC4436b);
            }
            C4488y removeFirst = c4449o.f11919e.removeFirst();
            Intrinsics.checkExpressionValueIsNotNull(removeFirst, "headersQueue.removeFirst()");
            headerBlock = removeFirst;
        }
        EnumC4377e0 protocol = this.f11898d;
        Intrinsics.checkParameterIsNotNull(headerBlock, "headerBlock");
        Intrinsics.checkParameterIsNotNull(protocol, "protocol");
        ArrayList arrayList = new ArrayList(20);
        int size = headerBlock.size();
        C4433j c4433j = null;
        for (int i2 = 0; i2 < size; i2++) {
            String name = headerBlock.m5278b(i2);
            String value = headerBlock.m5280d(i2);
            if (Intrinsics.areEqual(name, ":status")) {
                c4433j = C4433j.m5144a("HTTP/1.1 " + value);
            } else if (!f11896b.contains(name)) {
                Intrinsics.checkParameterIsNotNull(name, "name");
                Intrinsics.checkParameterIsNotNull(value, "value");
                arrayList.add(name);
                arrayList.add(StringsKt__StringsKt.trim((CharSequence) value).toString());
            }
        }
        if (c4433j == null) {
            throw new ProtocolException("Expected ':status' header not present");
        }
        C4389k0.a aVar = new C4389k0.a();
        aVar.m4996g(protocol);
        aVar.f11500c = c4433j.f11749b;
        aVar.m4995f(c4433j.f11750c);
        Object[] array = arrayList.toArray(new String[0]);
        if (array == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
        }
        aVar.m4994e(new C4488y((String[]) array, null));
        if (z && aVar.f11500c == 100) {
            return null;
        }
        return aVar;
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @NotNull
    /* renamed from: e */
    public C4418h mo5131e() {
        return this.f11900f;
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: f */
    public void mo5132f() {
        this.f11902h.f11824E.flush();
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    /* renamed from: g */
    public long mo5133g(@NotNull C4389k0 response) {
        Intrinsics.checkParameterIsNotNull(response, "response");
        if (C4428e.m5135a(response)) {
            return C4401c.m5026k(response);
        }
        return 0L;
    }

    @Override // p458k.p459p0.p463g.InterfaceC4427d
    @NotNull
    /* renamed from: h */
    public InterfaceC4762x mo5134h(@NotNull C4381g0 request, long j2) {
        Intrinsics.checkParameterIsNotNull(request, "request");
        C4449o c4449o = this.f11897c;
        if (c4449o == null) {
            Intrinsics.throwNpe();
        }
        return c4449o.m5197g();
    }
}
