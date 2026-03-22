package p458k;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.SSLSocket;
import kotlin.Deprecated;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.comparisons.ComparisonsKt__ComparisonsKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4386j;
import p458k.p459p0.C4401c;

/* renamed from: k.m */
/* loaded from: classes3.dex */
public final class C4392m {

    /* renamed from: a */
    public static final C4386j[] f11515a;

    /* renamed from: b */
    public static final C4386j[] f11516b;

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final C4392m f11517c;

    /* renamed from: d */
    @JvmField
    @NotNull
    public static final C4392m f11518d;

    /* renamed from: e */
    public final boolean f11519e;

    /* renamed from: f */
    public final boolean f11520f;

    /* renamed from: g */
    public final String[] f11521g;

    /* renamed from: h */
    public final String[] f11522h;

    /* renamed from: k.m$a */
    public static final class a {

        /* renamed from: a */
        public boolean f11523a;

        /* renamed from: b */
        @Nullable
        public String[] f11524b;

        /* renamed from: c */
        @Nullable
        public String[] f11525c;

        /* renamed from: d */
        public boolean f11526d;

        public a(boolean z) {
            this.f11523a = z;
        }

        @NotNull
        /* renamed from: a */
        public final C4392m m5001a() {
            return new C4392m(this.f11523a, this.f11526d, this.f11524b, this.f11525c);
        }

        @NotNull
        /* renamed from: b */
        public final a m5002b(@NotNull String... cipherSuites) {
            Intrinsics.checkParameterIsNotNull(cipherSuites, "cipherSuites");
            if (!this.f11523a) {
                throw new IllegalArgumentException("no cipher suites for cleartext connections".toString());
            }
            if (!(!(cipherSuites.length == 0))) {
                throw new IllegalArgumentException("At least one cipher suite is required".toString());
            }
            Object clone = cipherSuites.clone();
            if (clone == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<kotlin.String>");
            }
            this.f11524b = (String[]) clone;
            return this;
        }

        @NotNull
        /* renamed from: c */
        public final a m5003c(@NotNull C4386j... cipherSuites) {
            Intrinsics.checkParameterIsNotNull(cipherSuites, "cipherSuites");
            if (!this.f11523a) {
                throw new IllegalArgumentException("no cipher suites for cleartext connections".toString());
            }
            ArrayList arrayList = new ArrayList(cipherSuites.length);
            for (C4386j c4386j : cipherSuites) {
                arrayList.add(c4386j.f11482t);
            }
            Object[] array = arrayList.toArray(new String[0]);
            if (array == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            String[] strArr = (String[]) array;
            m5002b((String[]) Arrays.copyOf(strArr, strArr.length));
            return this;
        }

        @Deprecated(message = "since OkHttp 3.13 all TLS-connections are expected to support TLS extensions.\nIn a future release setting this to true will be unnecessary and setting it to false\nwill have no effect.")
        @NotNull
        /* renamed from: d */
        public final a m5004d(boolean z) {
            if (!this.f11523a) {
                throw new IllegalArgumentException("no TLS extensions for cleartext connections".toString());
            }
            this.f11526d = z;
            return this;
        }

        @NotNull
        /* renamed from: e */
        public final a m5005e(@NotNull String... tlsVersions) {
            Intrinsics.checkParameterIsNotNull(tlsVersions, "tlsVersions");
            if (!this.f11523a) {
                throw new IllegalArgumentException("no TLS versions for cleartext connections".toString());
            }
            if (!(!(tlsVersions.length == 0))) {
                throw new IllegalArgumentException("At least one TLS version is required".toString());
            }
            Object clone = tlsVersions.clone();
            if (clone == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<kotlin.String>");
            }
            this.f11525c = (String[]) clone;
            return this;
        }

        @NotNull
        /* renamed from: f */
        public final a m5006f(@NotNull EnumC4397o0... tlsVersions) {
            Intrinsics.checkParameterIsNotNull(tlsVersions, "tlsVersions");
            if (!this.f11523a) {
                throw new IllegalArgumentException("no TLS versions for cleartext connections".toString());
            }
            ArrayList arrayList = new ArrayList(tlsVersions.length);
            for (EnumC4397o0 enumC4397o0 : tlsVersions) {
                arrayList.add(enumC4397o0.f11538k);
            }
            Object[] array = arrayList.toArray(new String[0]);
            if (array == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            String[] strArr = (String[]) array;
            m5005e((String[]) Arrays.copyOf(strArr, strArr.length));
            return this;
        }

        public a(@NotNull C4392m connectionSpec) {
            Intrinsics.checkParameterIsNotNull(connectionSpec, "connectionSpec");
            this.f11523a = connectionSpec.f11519e;
            this.f11524b = connectionSpec.f11521g;
            this.f11525c = connectionSpec.f11522h;
            this.f11526d = connectionSpec.f11520f;
        }
    }

    static {
        C4386j c4386j = C4386j.f11478p;
        C4386j c4386j2 = C4386j.f11479q;
        C4386j c4386j3 = C4386j.f11480r;
        C4386j c4386j4 = C4386j.f11472j;
        C4386j c4386j5 = C4386j.f11474l;
        C4386j c4386j6 = C4386j.f11473k;
        C4386j c4386j7 = C4386j.f11475m;
        C4386j c4386j8 = C4386j.f11477o;
        C4386j c4386j9 = C4386j.f11476n;
        C4386j[] c4386jArr = {c4386j, c4386j2, c4386j3, c4386j4, c4386j5, c4386j6, c4386j7, c4386j8, c4386j9};
        f11515a = c4386jArr;
        C4386j[] c4386jArr2 = {c4386j, c4386j2, c4386j3, c4386j4, c4386j5, c4386j6, c4386j7, c4386j8, c4386j9, C4386j.f11470h, C4386j.f11471i, C4386j.f11468f, C4386j.f11469g, C4386j.f11466d, C4386j.f11467e, C4386j.f11465c};
        f11516b = c4386jArr2;
        a aVar = new a(true);
        aVar.m5003c((C4386j[]) Arrays.copyOf(c4386jArr, c4386jArr.length));
        EnumC4397o0 enumC4397o0 = EnumC4397o0.TLS_1_3;
        EnumC4397o0 enumC4397o02 = EnumC4397o0.TLS_1_2;
        aVar.m5006f(enumC4397o0, enumC4397o02);
        aVar.m5004d(true);
        aVar.m5001a();
        a aVar2 = new a(true);
        aVar2.m5003c((C4386j[]) Arrays.copyOf(c4386jArr2, c4386jArr2.length));
        aVar2.m5006f(enumC4397o0, enumC4397o02);
        aVar2.m5004d(true);
        f11517c = aVar2.m5001a();
        a aVar3 = new a(true);
        aVar3.m5003c((C4386j[]) Arrays.copyOf(c4386jArr2, c4386jArr2.length));
        aVar3.m5006f(enumC4397o0, enumC4397o02, EnumC4397o0.TLS_1_1, EnumC4397o0.TLS_1_0);
        aVar3.m5004d(true);
        aVar3.m5001a();
        f11518d = new C4392m(false, false, null, null);
    }

    public C4392m(boolean z, boolean z2, @Nullable String[] strArr, @Nullable String[] strArr2) {
        this.f11519e = z;
        this.f11520f = z2;
        this.f11521g = strArr;
        this.f11522h = strArr2;
    }

    @JvmName(name = "cipherSuites")
    @Nullable
    /* renamed from: a */
    public final List<C4386j> m4998a() {
        String[] strArr = this.f11521g;
        if (strArr == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(strArr.length);
        for (String str : strArr) {
            arrayList.add(C4386j.f11481s.m4984b(str));
        }
        return CollectionsKt___CollectionsKt.toList(arrayList);
    }

    /* renamed from: b */
    public final boolean m4999b(@NotNull SSLSocket socket) {
        Intrinsics.checkParameterIsNotNull(socket, "socket");
        if (!this.f11519e) {
            return false;
        }
        String[] strArr = this.f11522h;
        if (strArr != null && !C4401c.m5025j(strArr, socket.getEnabledProtocols(), ComparisonsKt__ComparisonsKt.naturalOrder())) {
            return false;
        }
        String[] strArr2 = this.f11521g;
        if (strArr2 == null) {
            return true;
        }
        String[] enabledCipherSuites = socket.getEnabledCipherSuites();
        C4386j.b bVar = C4386j.f11481s;
        Comparator<String> comparator = C4386j.f11463a;
        return C4401c.m5025j(strArr2, enabledCipherSuites, C4386j.f11463a);
    }

    @JvmName(name = "tlsVersions")
    @Nullable
    /* renamed from: c */
    public final List<EnumC4397o0> m5000c() {
        String[] strArr = this.f11522h;
        if (strArr == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(strArr.length);
        for (String str : strArr) {
            arrayList.add(EnumC4397o0.f11537j.m5012a(str));
        }
        return CollectionsKt___CollectionsKt.toList(arrayList);
    }

    public boolean equals(@Nullable Object obj) {
        if (!(obj instanceof C4392m)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        boolean z = this.f11519e;
        C4392m c4392m = (C4392m) obj;
        if (z != c4392m.f11519e) {
            return false;
        }
        return !z || (Arrays.equals(this.f11521g, c4392m.f11521g) && Arrays.equals(this.f11522h, c4392m.f11522h) && this.f11520f == c4392m.f11520f);
    }

    public int hashCode() {
        if (!this.f11519e) {
            return 17;
        }
        String[] strArr = this.f11521g;
        int hashCode = (527 + (strArr != null ? Arrays.hashCode(strArr) : 0)) * 31;
        String[] strArr2 = this.f11522h;
        return ((hashCode + (strArr2 != null ? Arrays.hashCode(strArr2) : 0)) * 31) + (!this.f11520f ? 1 : 0);
    }

    @NotNull
    public String toString() {
        if (!this.f11519e) {
            return "ConnectionSpec()";
        }
        StringBuilder m590L = C1499a.m590L("ConnectionSpec(", "cipherSuites=");
        m590L.append(Objects.toString(m4998a(), "[all enabled]"));
        m590L.append(", ");
        m590L.append("tlsVersions=");
        m590L.append(Objects.toString(m5000c(), "[all enabled]"));
        m590L.append(", ");
        m590L.append("supportsTlsExtensions=");
        m590L.append(this.f11520f);
        m590L.append(')');
        return m590L.toString();
    }
}
