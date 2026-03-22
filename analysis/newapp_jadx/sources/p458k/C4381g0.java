package p458k;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import kotlin.Pair;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.MapsKt__MapsKt;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4488y;
import p458k.C4489z;
import p458k.p459p0.C4401c;
import p458k.p459p0.p463g.C4429f;

/* renamed from: k.g0 */
/* loaded from: classes3.dex */
public final class C4381g0 {

    /* renamed from: a */
    public C4376e f11439a;

    /* renamed from: b */
    @NotNull
    public final C4489z f11440b;

    /* renamed from: c */
    @NotNull
    public final String f11441c;

    /* renamed from: d */
    @NotNull
    public final C4488y f11442d;

    /* renamed from: e */
    @Nullable
    public final AbstractC4387j0 f11443e;

    /* renamed from: f */
    @NotNull
    public final Map<Class<?>, Object> f11444f;

    public C4381g0(@NotNull C4489z url, @NotNull String method, @NotNull C4488y headers, @Nullable AbstractC4387j0 abstractC4387j0, @NotNull Map<Class<?>, ? extends Object> tags) {
        Intrinsics.checkParameterIsNotNull(url, "url");
        Intrinsics.checkParameterIsNotNull(method, "method");
        Intrinsics.checkParameterIsNotNull(headers, "headers");
        Intrinsics.checkParameterIsNotNull(tags, "tags");
        this.f11440b = url;
        this.f11441c = method;
        this.f11442d = headers;
        this.f11443e = abstractC4387j0;
        this.f11444f = tags;
    }

    @JvmName(name = "cacheControl")
    @NotNull
    /* renamed from: a */
    public final C4376e m4969a() {
        C4376e c4376e = this.f11439a;
        if (c4376e != null) {
            return c4376e;
        }
        C4376e m4961b = C4376e.f11408a.m4961b(this.f11442d);
        this.f11439a = m4961b;
        return m4961b;
    }

    @Nullable
    /* renamed from: b */
    public final String m4970b(@NotNull String name) {
        Intrinsics.checkParameterIsNotNull(name, "name");
        return this.f11442d.m5277a(name);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Request{method=");
        m586H.append(this.f11441c);
        m586H.append(", url=");
        m586H.append(this.f11440b);
        if (this.f11442d.size() != 0) {
            m586H.append(", headers=[");
            int i2 = 0;
            for (Pair<? extends String, ? extends String> pair : this.f11442d) {
                int i3 = i2 + 1;
                if (i2 < 0) {
                    CollectionsKt__CollectionsKt.throwIndexOverflow();
                }
                Pair<? extends String, ? extends String> pair2 = pair;
                String component1 = pair2.component1();
                String component2 = pair2.component2();
                if (i2 > 0) {
                    m586H.append(", ");
                }
                m586H.append(component1);
                m586H.append(':');
                m586H.append(component2);
                i2 = i3;
            }
            m586H.append(']');
        }
        if (!this.f11444f.isEmpty()) {
            m586H.append(", tags=");
            m586H.append(this.f11444f);
        }
        m586H.append('}');
        String sb = m586H.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb, "StringBuilder().apply(builderAction).toString()");
        return sb;
    }

    /* renamed from: k.g0$a */
    public static class a {

        /* renamed from: a */
        @Nullable
        public C4489z f11445a;

        /* renamed from: b */
        @NotNull
        public String f11446b;

        /* renamed from: c */
        @NotNull
        public C4488y.a f11447c;

        /* renamed from: d */
        @Nullable
        public AbstractC4387j0 f11448d;

        /* renamed from: e */
        @NotNull
        public Map<Class<?>, Object> f11449e;

        public a() {
            this.f11449e = new LinkedHashMap();
            this.f11446b = "GET";
            this.f11447c = new C4488y.a();
        }

        @NotNull
        /* renamed from: a */
        public a m4971a(@NotNull String name, @NotNull String value) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            this.f11447c.m5282a(name, value);
            return this;
        }

        @NotNull
        /* renamed from: b */
        public C4381g0 m4972b() {
            Map unmodifiableMap;
            C4489z c4489z = this.f11445a;
            if (c4489z == null) {
                throw new IllegalStateException("url == null".toString());
            }
            String str = this.f11446b;
            C4488y m5285d = this.f11447c.m5285d();
            AbstractC4387j0 abstractC4387j0 = this.f11448d;
            Map<Class<?>, Object> toImmutableMap = this.f11449e;
            byte[] bArr = C4401c.f11556a;
            Intrinsics.checkParameterIsNotNull(toImmutableMap, "$this$toImmutableMap");
            if (toImmutableMap.isEmpty()) {
                unmodifiableMap = MapsKt__MapsKt.emptyMap();
            } else {
                unmodifiableMap = Collections.unmodifiableMap(new LinkedHashMap(toImmutableMap));
                Intrinsics.checkExpressionValueIsNotNull(unmodifiableMap, "Collections.unmodifiableMap(LinkedHashMap(this))");
            }
            return new C4381g0(c4489z, str, m5285d, abstractC4387j0, unmodifiableMap);
        }

        @NotNull
        /* renamed from: c */
        public a m4973c(@NotNull String name, @NotNull String value) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            C4488y.a aVar = this.f11447c;
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
        /* renamed from: d */
        public a m4974d(@NotNull C4488y headers) {
            Intrinsics.checkParameterIsNotNull(headers, "headers");
            this.f11447c = headers.m5279c();
            return this;
        }

        @NotNull
        /* renamed from: e */
        public a m4975e(@NotNull String method, @Nullable AbstractC4387j0 abstractC4387j0) {
            Intrinsics.checkParameterIsNotNull(method, "method");
            if (!(method.length() > 0)) {
                throw new IllegalArgumentException("method.isEmpty() == true".toString());
            }
            if (abstractC4387j0 == null) {
                Intrinsics.checkParameterIsNotNull(method, "method");
                if (!(!(Intrinsics.areEqual(method, "POST") || Intrinsics.areEqual(method, "PUT") || Intrinsics.areEqual(method, "PATCH") || Intrinsics.areEqual(method, "PROPPATCH") || Intrinsics.areEqual(method, "REPORT")))) {
                    throw new IllegalArgumentException(C1499a.m639y("method ", method, " must have a request body.").toString());
                }
            } else if (!C4429f.m5137a(method)) {
                throw new IllegalArgumentException(C1499a.m639y("method ", method, " must not have a request body.").toString());
            }
            this.f11446b = method;
            this.f11448d = abstractC4387j0;
            return this;
        }

        @NotNull
        /* renamed from: f */
        public a m4976f(@NotNull String name) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            this.f11447c.m5287f(name);
            return this;
        }

        @NotNull
        /* renamed from: g */
        public <T> a m4977g(@NotNull Class<? super T> type, @Nullable T t) {
            Intrinsics.checkParameterIsNotNull(type, "type");
            if (t == null) {
                this.f11449e.remove(type);
            } else {
                if (this.f11449e.isEmpty()) {
                    this.f11449e = new LinkedHashMap();
                }
                Map<Class<?>, Object> map = this.f11449e;
                T cast = type.cast(t);
                if (cast == null) {
                    Intrinsics.throwNpe();
                }
                map.put(type, cast);
            }
            return this;
        }

        @NotNull
        /* renamed from: h */
        public a m4978h(@NotNull String toHttpUrl) {
            Intrinsics.checkParameterIsNotNull(toHttpUrl, "url");
            if (StringsKt__StringsJVMKt.startsWith(toHttpUrl, "ws:", true)) {
                StringBuilder m586H = C1499a.m586H("http:");
                String substring = toHttpUrl.substring(3);
                Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.String).substring(startIndex)");
                m586H.append(substring);
                toHttpUrl = m586H.toString();
            } else if (StringsKt__StringsJVMKt.startsWith(toHttpUrl, "wss:", true)) {
                StringBuilder m586H2 = C1499a.m586H("https:");
                String substring2 = toHttpUrl.substring(4);
                Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
                m586H2.append(substring2);
                toHttpUrl = m586H2.toString();
            }
            Intrinsics.checkParameterIsNotNull(toHttpUrl, "$this$toHttpUrl");
            C4489z.a aVar = new C4489z.a();
            aVar.m5302d(null, toHttpUrl);
            m4979i(aVar.m5299a());
            return this;
        }

        @NotNull
        /* renamed from: i */
        public a m4979i(@NotNull C4489z url) {
            Intrinsics.checkParameterIsNotNull(url, "url");
            this.f11445a = url;
            return this;
        }

        public a(@NotNull C4381g0 request) {
            Map<Class<?>, Object> mutableMap;
            Intrinsics.checkParameterIsNotNull(request, "request");
            this.f11449e = new LinkedHashMap();
            this.f11445a = request.f11440b;
            this.f11446b = request.f11441c;
            this.f11448d = request.f11443e;
            if (request.f11444f.isEmpty()) {
                mutableMap = new LinkedHashMap<>();
            } else {
                mutableMap = MapsKt__MapsKt.toMutableMap(request.f11444f);
            }
            this.f11449e = mutableMap;
            this.f11447c = request.f11442d.m5279c();
        }
    }
}
