package B2;

import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.SSLSocket;
import k2.AbstractC0605a;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class l {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final C0171i[] f350e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final C0171i[] f351f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final l f352g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final l f353h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final l f354i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final l f355j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final b f356k = new b(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f357a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f358b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String[] f359c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final String[] f360d;

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f361a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private String[] f362b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private String[] f363c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f364d;

        public a(boolean z3) {
            this.f361a = z3;
        }

        public final l a() {
            return new l(this.f361a, this.f364d, this.f362b, this.f363c);
        }

        public final a b(C0171i... c0171iArr) {
            t2.j.f(c0171iArr, "cipherSuites");
            if (!this.f361a) {
                throw new IllegalArgumentException("no cipher suites for cleartext connections");
            }
            ArrayList arrayList = new ArrayList(c0171iArr.length);
            for (C0171i c0171i : c0171iArr) {
                arrayList.add(c0171i.c());
            }
            Object[] array = arrayList.toArray(new String[0]);
            if (array == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            String[] strArr = (String[]) array;
            return c((String[]) Arrays.copyOf(strArr, strArr.length));
        }

        public final a c(String... strArr) throws CloneNotSupportedException {
            t2.j.f(strArr, "cipherSuites");
            if (!this.f361a) {
                throw new IllegalArgumentException("no cipher suites for cleartext connections");
            }
            if (strArr.length == 0) {
                throw new IllegalArgumentException("At least one cipher suite is required");
            }
            Object objClone = strArr.clone();
            if (objClone == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<kotlin.String>");
            }
            this.f362b = (String[]) objClone;
            return this;
        }

        public final a d(boolean z3) {
            if (!this.f361a) {
                throw new IllegalArgumentException("no TLS extensions for cleartext connections");
            }
            this.f364d = z3;
            return this;
        }

        public final a e(G... gArr) {
            t2.j.f(gArr, "tlsVersions");
            if (!this.f361a) {
                throw new IllegalArgumentException("no TLS versions for cleartext connections");
            }
            ArrayList arrayList = new ArrayList(gArr.length);
            for (G g3 : gArr) {
                arrayList.add(g3.a());
            }
            Object[] array = arrayList.toArray(new String[0]);
            if (array == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            String[] strArr = (String[]) array;
            return f((String[]) Arrays.copyOf(strArr, strArr.length));
        }

        public final a f(String... strArr) throws CloneNotSupportedException {
            t2.j.f(strArr, "tlsVersions");
            if (!this.f361a) {
                throw new IllegalArgumentException("no TLS versions for cleartext connections");
            }
            if (strArr.length == 0) {
                throw new IllegalArgumentException("At least one TLS version is required");
            }
            Object objClone = strArr.clone();
            if (objClone == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<kotlin.String>");
            }
            this.f363c = (String[]) objClone;
            return this;
        }

        public a(l lVar) {
            t2.j.f(lVar, "connectionSpec");
            this.f361a = lVar.f();
            this.f362b = lVar.f359c;
            this.f363c = lVar.f360d;
            this.f364d = lVar.h();
        }
    }

    public static final class b {
        private b() {
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static {
        C0171i c0171i = C0171i.f318n1;
        C0171i c0171i2 = C0171i.f321o1;
        C0171i c0171i3 = C0171i.f324p1;
        C0171i c0171i4 = C0171i.f277Z0;
        C0171i c0171i5 = C0171i.f288d1;
        C0171i c0171i6 = C0171i.f279a1;
        C0171i c0171i7 = C0171i.f291e1;
        C0171i c0171i8 = C0171i.f309k1;
        C0171i c0171i9 = C0171i.f306j1;
        C0171i[] c0171iArr = {c0171i, c0171i2, c0171i3, c0171i4, c0171i5, c0171i6, c0171i7, c0171i8, c0171i9};
        f350e = c0171iArr;
        C0171i[] c0171iArr2 = {c0171i, c0171i2, c0171i3, c0171i4, c0171i5, c0171i6, c0171i7, c0171i8, c0171i9, C0171i.f247K0, C0171i.f249L0, C0171i.f302i0, C0171i.f305j0, C0171i.f238G, C0171i.f246K, C0171i.f307k};
        f351f = c0171iArr2;
        a aVarB = new a(true).b((C0171i[]) Arrays.copyOf(c0171iArr, c0171iArr.length));
        G g3 = G.TLS_1_3;
        G g4 = G.TLS_1_2;
        f352g = aVarB.e(g3, g4).d(true).a();
        f353h = new a(true).b((C0171i[]) Arrays.copyOf(c0171iArr2, c0171iArr2.length)).e(g3, g4).d(true).a();
        f354i = new a(true).b((C0171i[]) Arrays.copyOf(c0171iArr2, c0171iArr2.length)).e(g3, g4, G.TLS_1_1, G.TLS_1_0).d(true).a();
        f355j = new a(false).a();
    }

    public l(boolean z3, boolean z4, String[] strArr, String[] strArr2) {
        this.f357a = z3;
        this.f358b = z4;
        this.f359c = strArr;
        this.f360d = strArr2;
    }

    private final l g(SSLSocket sSLSocket, boolean z3) throws CloneNotSupportedException {
        String[] enabledCipherSuites;
        String[] enabledProtocols;
        if (this.f359c != null) {
            String[] enabledCipherSuites2 = sSLSocket.getEnabledCipherSuites();
            t2.j.e(enabledCipherSuites2, "sslSocket.enabledCipherSuites");
            enabledCipherSuites = C2.c.B(enabledCipherSuites2, this.f359c, C0171i.f333s1.c());
        } else {
            enabledCipherSuites = sSLSocket.getEnabledCipherSuites();
        }
        if (this.f360d != null) {
            String[] enabledProtocols2 = sSLSocket.getEnabledProtocols();
            t2.j.e(enabledProtocols2, "sslSocket.enabledProtocols");
            enabledProtocols = C2.c.B(enabledProtocols2, this.f360d, AbstractC0605a.b());
        } else {
            enabledProtocols = sSLSocket.getEnabledProtocols();
        }
        String[] supportedCipherSuites = sSLSocket.getSupportedCipherSuites();
        t2.j.e(supportedCipherSuites, "supportedCipherSuites");
        int iU = C2.c.u(supportedCipherSuites, "TLS_FALLBACK_SCSV", C0171i.f333s1.c());
        if (z3 && iU != -1) {
            t2.j.e(enabledCipherSuites, "cipherSuitesIntersection");
            String str = supportedCipherSuites[iU];
            t2.j.e(str, "supportedCipherSuites[indexOfFallbackScsv]");
            enabledCipherSuites = C2.c.l(enabledCipherSuites, str);
        }
        a aVar = new a(this);
        t2.j.e(enabledCipherSuites, "cipherSuitesIntersection");
        a aVarC = aVar.c((String[]) Arrays.copyOf(enabledCipherSuites, enabledCipherSuites.length));
        t2.j.e(enabledProtocols, "tlsVersionsIntersection");
        return aVarC.f((String[]) Arrays.copyOf(enabledProtocols, enabledProtocols.length)).a();
    }

    public final void c(SSLSocket sSLSocket, boolean z3) throws CloneNotSupportedException {
        t2.j.f(sSLSocket, "sslSocket");
        l lVarG = g(sSLSocket, z3);
        if (lVarG.i() != null) {
            sSLSocket.setEnabledProtocols(lVarG.f360d);
        }
        if (lVarG.d() != null) {
            sSLSocket.setEnabledCipherSuites(lVarG.f359c);
        }
    }

    public final List d() {
        String[] strArr = this.f359c;
        if (strArr == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(strArr.length);
        for (String str : strArr) {
            arrayList.add(C0171i.f333s1.b(str));
        }
        return AbstractC0586n.T(arrayList);
    }

    public final boolean e(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "socket");
        if (!this.f357a) {
            return false;
        }
        String[] strArr = this.f360d;
        if (strArr != null && !C2.c.r(strArr, sSLSocket.getEnabledProtocols(), AbstractC0605a.b())) {
            return false;
        }
        String[] strArr2 = this.f359c;
        return strArr2 == null || C2.c.r(strArr2, sSLSocket.getEnabledCipherSuites(), C0171i.f333s1.c());
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof l)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        boolean z3 = this.f357a;
        l lVar = (l) obj;
        if (z3 != lVar.f357a) {
            return false;
        }
        return !z3 || (Arrays.equals(this.f359c, lVar.f359c) && Arrays.equals(this.f360d, lVar.f360d) && this.f358b == lVar.f358b);
    }

    public final boolean f() {
        return this.f357a;
    }

    public final boolean h() {
        return this.f358b;
    }

    public int hashCode() {
        if (!this.f357a) {
            return 17;
        }
        String[] strArr = this.f359c;
        int iHashCode = (527 + (strArr != null ? Arrays.hashCode(strArr) : 0)) * 31;
        String[] strArr2 = this.f360d;
        return ((iHashCode + (strArr2 != null ? Arrays.hashCode(strArr2) : 0)) * 31) + (!this.f358b ? 1 : 0);
    }

    public final List i() {
        String[] strArr = this.f360d;
        if (strArr == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(strArr.length);
        for (String str : strArr) {
            arrayList.add(G.f144i.a(str));
        }
        return AbstractC0586n.T(arrayList);
    }

    public String toString() {
        if (!this.f357a) {
            return "ConnectionSpec()";
        }
        return "ConnectionSpec(cipherSuites=" + Objects.toString(d(), "[all enabled]") + ", tlsVersions=" + Objects.toString(i(), "[all enabled]") + ", supportsTlsExtensions=" + this.f358b + ')';
    }
}
