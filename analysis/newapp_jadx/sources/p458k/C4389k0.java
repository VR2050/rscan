package p458k;

import java.io.Closeable;
import java.util.Objects;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4488y;
import p458k.p459p0.p462f.C4413c;

/* renamed from: k.k0 */
/* loaded from: classes3.dex */
public final class C4389k0 implements Closeable {

    /* renamed from: c */
    public C4376e f11484c;

    /* renamed from: e */
    @NotNull
    public final C4381g0 f11485e;

    /* renamed from: f */
    @NotNull
    public final EnumC4377e0 f11486f;

    /* renamed from: g */
    @NotNull
    public final String f11487g;

    /* renamed from: h */
    public final int f11488h;

    /* renamed from: i */
    @Nullable
    public final C4487x f11489i;

    /* renamed from: j */
    @NotNull
    public final C4488y f11490j;

    /* renamed from: k */
    @Nullable
    public final AbstractC4393m0 f11491k;

    /* renamed from: l */
    @Nullable
    public final C4389k0 f11492l;

    /* renamed from: m */
    @Nullable
    public final C4389k0 f11493m;

    /* renamed from: n */
    @Nullable
    public final C4389k0 f11494n;

    /* renamed from: o */
    public final long f11495o;

    /* renamed from: p */
    public final long f11496p;

    /* renamed from: q */
    @Nullable
    public final C4413c f11497q;

    public C4389k0(@NotNull C4381g0 request, @NotNull EnumC4377e0 protocol, @NotNull String message, int i2, @Nullable C4487x c4487x, @NotNull C4488y headers, @Nullable AbstractC4393m0 abstractC4393m0, @Nullable C4389k0 c4389k0, @Nullable C4389k0 c4389k02, @Nullable C4389k0 c4389k03, long j2, long j3, @Nullable C4413c c4413c) {
        Intrinsics.checkParameterIsNotNull(request, "request");
        Intrinsics.checkParameterIsNotNull(protocol, "protocol");
        Intrinsics.checkParameterIsNotNull(message, "message");
        Intrinsics.checkParameterIsNotNull(headers, "headers");
        this.f11485e = request;
        this.f11486f = protocol;
        this.f11487g = message;
        this.f11488h = i2;
        this.f11489i = c4487x;
        this.f11490j = headers;
        this.f11491k = abstractC4393m0;
        this.f11492l = c4389k0;
        this.f11493m = c4389k02;
        this.f11494n = c4389k03;
        this.f11495o = j2;
        this.f11496p = j3;
        this.f11497q = c4413c;
    }

    /* renamed from: d */
    public static String m4987d(C4389k0 c4389k0, String name, String str, int i2) {
        int i3 = i2 & 2;
        Objects.requireNonNull(c4389k0);
        Intrinsics.checkParameterIsNotNull(name, "name");
        String m5277a = c4389k0.f11490j.m5277a(name);
        if (m5277a != null) {
            return m5277a;
        }
        return null;
    }

    @JvmName(name = "cacheControl")
    @NotNull
    /* renamed from: b */
    public final C4376e m4988b() {
        C4376e c4376e = this.f11484c;
        if (c4376e != null) {
            return c4376e;
        }
        C4376e m4961b = C4376e.f11408a.m4961b(this.f11490j);
        this.f11484c = m4961b;
        return m4961b;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        AbstractC4393m0 abstractC4393m0 = this.f11491k;
        if (abstractC4393m0 == null) {
            throw new IllegalStateException("response is not eligible for a body and must not be closed".toString());
        }
        abstractC4393m0.close();
    }

    /* renamed from: e */
    public final boolean m4989e() {
        int i2 = this.f11488h;
        return 200 <= i2 && 299 >= i2;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Response{protocol=");
        m586H.append(this.f11486f);
        m586H.append(", code=");
        m586H.append(this.f11488h);
        m586H.append(", message=");
        m586H.append(this.f11487g);
        m586H.append(", url=");
        m586H.append(this.f11485e.f11440b);
        m586H.append('}');
        return m586H.toString();
    }

    /* renamed from: k.k0$a */
    public static class a {

        /* renamed from: a */
        @Nullable
        public C4381g0 f11498a;

        /* renamed from: b */
        @Nullable
        public EnumC4377e0 f11499b;

        /* renamed from: c */
        public int f11500c;

        /* renamed from: d */
        @Nullable
        public String f11501d;

        /* renamed from: e */
        @Nullable
        public C4487x f11502e;

        /* renamed from: f */
        @NotNull
        public C4488y.a f11503f;

        /* renamed from: g */
        @Nullable
        public AbstractC4393m0 f11504g;

        /* renamed from: h */
        @Nullable
        public C4389k0 f11505h;

        /* renamed from: i */
        @Nullable
        public C4389k0 f11506i;

        /* renamed from: j */
        @Nullable
        public C4389k0 f11507j;

        /* renamed from: k */
        public long f11508k;

        /* renamed from: l */
        public long f11509l;

        /* renamed from: m */
        @Nullable
        public C4413c f11510m;

        public a() {
            this.f11500c = -1;
            this.f11503f = new C4488y.a();
        }

        @NotNull
        /* renamed from: a */
        public C4389k0 m4990a() {
            int i2 = this.f11500c;
            if (!(i2 >= 0)) {
                StringBuilder m586H = C1499a.m586H("code < 0: ");
                m586H.append(this.f11500c);
                throw new IllegalStateException(m586H.toString().toString());
            }
            C4381g0 c4381g0 = this.f11498a;
            if (c4381g0 == null) {
                throw new IllegalStateException("request == null".toString());
            }
            EnumC4377e0 enumC4377e0 = this.f11499b;
            if (enumC4377e0 == null) {
                throw new IllegalStateException("protocol == null".toString());
            }
            String str = this.f11501d;
            if (str != null) {
                return new C4389k0(c4381g0, enumC4377e0, str, i2, this.f11502e, this.f11503f.m5285d(), this.f11504g, this.f11505h, this.f11506i, this.f11507j, this.f11508k, this.f11509l, this.f11510m);
            }
            throw new IllegalStateException("message == null".toString());
        }

        @NotNull
        /* renamed from: b */
        public a m4991b(@Nullable C4389k0 c4389k0) {
            m4992c("cacheResponse", c4389k0);
            this.f11506i = c4389k0;
            return this;
        }

        /* renamed from: c */
        public final void m4992c(String str, C4389k0 c4389k0) {
            if (c4389k0 != null) {
                if (!(c4389k0.f11491k == null)) {
                    throw new IllegalArgumentException(C1499a.m637w(str, ".body != null").toString());
                }
                if (!(c4389k0.f11492l == null)) {
                    throw new IllegalArgumentException(C1499a.m637w(str, ".networkResponse != null").toString());
                }
                if (!(c4389k0.f11493m == null)) {
                    throw new IllegalArgumentException(C1499a.m637w(str, ".cacheResponse != null").toString());
                }
                if (!(c4389k0.f11494n == null)) {
                    throw new IllegalArgumentException(C1499a.m637w(str, ".priorResponse != null").toString());
                }
            }
        }

        @NotNull
        /* renamed from: d */
        public a m4993d(@NotNull String name, @NotNull String value) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            C4488y.a aVar = this.f11503f;
            Objects.requireNonNull(aVar);
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            C4488y.b bVar = C4488y.f12040c;
            bVar.m5288a(name);
            bVar.m5289b(value, name);
            aVar.m5287f(name);
            aVar.m5284c(name, value);
            return this;
        }

        @NotNull
        /* renamed from: e */
        public a m4994e(@NotNull C4488y headers) {
            Intrinsics.checkParameterIsNotNull(headers, "headers");
            this.f11503f = headers.m5279c();
            return this;
        }

        @NotNull
        /* renamed from: f */
        public a m4995f(@NotNull String message) {
            Intrinsics.checkParameterIsNotNull(message, "message");
            this.f11501d = message;
            return this;
        }

        @NotNull
        /* renamed from: g */
        public a m4996g(@NotNull EnumC4377e0 protocol) {
            Intrinsics.checkParameterIsNotNull(protocol, "protocol");
            this.f11499b = protocol;
            return this;
        }

        @NotNull
        /* renamed from: h */
        public a m4997h(@NotNull C4381g0 request) {
            Intrinsics.checkParameterIsNotNull(request, "request");
            this.f11498a = request;
            return this;
        }

        public a(@NotNull C4389k0 response) {
            Intrinsics.checkParameterIsNotNull(response, "response");
            this.f11500c = -1;
            this.f11498a = response.f11485e;
            this.f11499b = response.f11486f;
            this.f11500c = response.f11488h;
            this.f11501d = response.f11487g;
            this.f11502e = response.f11489i;
            this.f11503f = response.f11490j.m5279c();
            this.f11504g = response.f11491k;
            this.f11505h = response.f11492l;
            this.f11506i = response.f11493m;
            this.f11507j = response.f11494n;
            this.f11508k = response.f11495o;
            this.f11509l = response.f11496p;
            this.f11510m = response.f11497q;
        }
    }
}
