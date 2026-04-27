package B2;

import B2.x;
import java.io.EOFException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class y extends C {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final x f442g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final x f443h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final x f444i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final x f445j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final x f446k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static final byte[] f447l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static final byte[] f448m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static final byte[] f449n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    public static final b f450o = new b(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final x f451b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f452c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Q2.l f453d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final x f454e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final List f455f;

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Q2.l f456a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private x f457b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final List f458c;

        /* JADX WARN: Multi-variable type inference failed */
        public a() {
            this(null, 1, 0 == true ? 1 : 0);
        }

        public final a a(t tVar, C c3) {
            t2.j.f(c3, "body");
            b(c.f459c.a(tVar, c3));
            return this;
        }

        public final a b(c cVar) {
            t2.j.f(cVar, "part");
            this.f458c.add(cVar);
            return this;
        }

        public final y c() {
            if (this.f458c.isEmpty()) {
                throw new IllegalStateException("Multipart body must have at least one part.");
            }
            return new y(this.f456a, this.f457b, C2.c.R(this.f458c));
        }

        public final a d(x xVar) {
            t2.j.f(xVar, "type");
            if (t2.j.b(xVar.g(), "multipart")) {
                this.f457b = xVar;
                return this;
            }
            throw new IllegalArgumentException(("multipart != " + xVar).toString());
        }

        public a(String str) {
            t2.j.f(str, "boundary");
            this.f456a = Q2.l.f2556f.e(str);
            this.f457b = y.f442g;
            this.f458c = new ArrayList();
        }

        /* JADX WARN: Illegal instructions before constructor call */
        public /* synthetic */ a(String str, int i3, DefaultConstructorMarker defaultConstructorMarker) {
            if ((i3 & 1) != 0) {
                str = UUID.randomUUID().toString();
                t2.j.e(str, "UUID.randomUUID().toString()");
            }
            this(str);
        }
    }

    public static final class b {
        private b() {
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final class c {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final a f459c = new a(null);

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final t f460a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final C f461b;

        public static final class a {
            private a() {
            }

            public final c a(t tVar, C c3) {
                t2.j.f(c3, "body");
                DefaultConstructorMarker defaultConstructorMarker = null;
                if (!((tVar != null ? tVar.a("Content-Type") : null) == null)) {
                    throw new IllegalArgumentException("Unexpected header: Content-Type");
                }
                if ((tVar != null ? tVar.a("Content-Length") : null) == null) {
                    return new c(tVar, c3, defaultConstructorMarker);
                }
                throw new IllegalArgumentException("Unexpected header: Content-Length");
            }

            public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }
        }

        private c(t tVar, C c3) {
            this.f460a = tVar;
            this.f461b = c3;
        }

        public final C a() {
            return this.f461b;
        }

        public final t b() {
            return this.f460a;
        }

        public /* synthetic */ c(t tVar, C c3, DefaultConstructorMarker defaultConstructorMarker) {
            this(tVar, c3);
        }
    }

    static {
        x.a aVar = x.f437g;
        f442g = aVar.b("multipart/mixed");
        f443h = aVar.b("multipart/alternative");
        f444i = aVar.b("multipart/digest");
        f445j = aVar.b("multipart/parallel");
        f446k = aVar.b("multipart/form-data");
        f447l = new byte[]{(byte) 58, (byte) 32};
        f448m = new byte[]{(byte) 13, (byte) 10};
        byte b3 = (byte) 45;
        f449n = new byte[]{b3, b3};
    }

    public y(Q2.l lVar, x xVar, List list) {
        t2.j.f(lVar, "boundaryByteString");
        t2.j.f(xVar, "type");
        t2.j.f(list, "parts");
        this.f453d = lVar;
        this.f454e = xVar;
        this.f455f = list;
        this.f451b = x.f437g.b(xVar + "; boundary=" + i());
        this.f452c = -1L;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final long j(Q2.j jVar, boolean z3) throws EOFException {
        Q2.i iVar;
        if (z3) {
            jVar = new Q2.i();
            iVar = jVar;
        } else {
            iVar = 0;
        }
        int size = this.f455f.size();
        long j3 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            c cVar = (c) this.f455f.get(i3);
            t tVarB = cVar.b();
            C cA = cVar.a();
            t2.j.c(jVar);
            jVar.Q(f449n);
            jVar.z(this.f453d);
            jVar.Q(f448m);
            if (tVarB != null) {
                int size2 = tVarB.size();
                for (int i4 = 0; i4 < size2; i4++) {
                    jVar.j0(tVarB.b(i4)).Q(f447l).j0(tVarB.h(i4)).Q(f448m);
                }
            }
            x xVarB = cA.b();
            if (xVarB != null) {
                jVar.j0("Content-Type: ").j0(xVarB.toString()).Q(f448m);
            }
            long jA = cA.a();
            if (jA != -1) {
                jVar.j0("Content-Length: ").k0(jA).Q(f448m);
            } else if (z3) {
                t2.j.c(iVar);
                iVar.v();
                return -1L;
            }
            byte[] bArr = f448m;
            jVar.Q(bArr);
            if (z3) {
                j3 += jA;
            } else {
                cA.h(jVar);
            }
            jVar.Q(bArr);
        }
        t2.j.c(jVar);
        byte[] bArr2 = f449n;
        jVar.Q(bArr2);
        jVar.z(this.f453d);
        jVar.Q(bArr2);
        jVar.Q(f448m);
        if (!z3) {
            return j3;
        }
        t2.j.c(iVar);
        long jF0 = j3 + iVar.F0();
        iVar.v();
        return jF0;
    }

    @Override // B2.C
    public long a() throws EOFException {
        long j3 = this.f452c;
        if (j3 != -1) {
            return j3;
        }
        long j4 = j(null, true);
        this.f452c = j4;
        return j4;
    }

    @Override // B2.C
    public x b() {
        return this.f451b;
    }

    @Override // B2.C
    public void h(Q2.j jVar) throws EOFException {
        t2.j.f(jVar, "sink");
        j(jVar, false);
    }

    public final String i() {
        return this.f453d.z();
    }
}
