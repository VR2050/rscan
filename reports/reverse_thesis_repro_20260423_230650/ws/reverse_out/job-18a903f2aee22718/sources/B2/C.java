package B2;

import java.nio.charset.Charset;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public abstract class C {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f97a = new a(null);

    public static final class a {

        /* JADX INFO: renamed from: B2.C$a$a, reason: collision with other inner class name */
        public static final class C0002a extends C {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ Q2.l f98b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ x f99c;

            C0002a(Q2.l lVar, x xVar) {
                this.f98b = lVar;
                this.f99c = xVar;
            }

            @Override // B2.C
            public long a() {
                return this.f98b.v();
            }

            @Override // B2.C
            public x b() {
                return this.f99c;
            }

            @Override // B2.C
            public void h(Q2.j jVar) {
                t2.j.f(jVar, "sink");
                jVar.z(this.f98b);
            }
        }

        public static final class b extends C {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ byte[] f100b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ x f101c;

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            final /* synthetic */ int f102d;

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            final /* synthetic */ int f103e;

            b(byte[] bArr, x xVar, int i3, int i4) {
                this.f100b = bArr;
                this.f101c = xVar;
                this.f102d = i3;
                this.f103e = i4;
            }

            @Override // B2.C
            public long a() {
                return this.f102d;
            }

            @Override // B2.C
            public x b() {
                return this.f101c;
            }

            @Override // B2.C
            public void h(Q2.j jVar) {
                t2.j.f(jVar, "sink");
                jVar.j(this.f100b, this.f103e, this.f102d);
            }
        }

        private a() {
        }

        public static /* synthetic */ C g(a aVar, x xVar, byte[] bArr, int i3, int i4, int i5, Object obj) {
            if ((i5 & 4) != 0) {
                i3 = 0;
            }
            if ((i5 & 8) != 0) {
                i4 = bArr.length;
            }
            return aVar.c(xVar, bArr, i3, i4);
        }

        public static /* synthetic */ C h(a aVar, byte[] bArr, x xVar, int i3, int i4, int i5, Object obj) {
            if ((i5 & 1) != 0) {
                xVar = null;
            }
            if ((i5 & 2) != 0) {
                i3 = 0;
            }
            if ((i5 & 4) != 0) {
                i4 = bArr.length;
            }
            return aVar.f(bArr, xVar, i3, i4);
        }

        public final C a(x xVar, Q2.l lVar) {
            t2.j.f(lVar, "content");
            return d(lVar, xVar);
        }

        public final C b(x xVar, String str) {
            t2.j.f(str, "content");
            return e(str, xVar);
        }

        public final C c(x xVar, byte[] bArr, int i3, int i4) {
            t2.j.f(bArr, "content");
            return f(bArr, xVar, i3, i4);
        }

        public final C d(Q2.l lVar, x xVar) {
            t2.j.f(lVar, "$this$toRequestBody");
            return new C0002a(lVar, xVar);
        }

        public final C e(String str, x xVar) {
            t2.j.f(str, "$this$toRequestBody");
            Charset charset = z2.d.f10544b;
            if (xVar != null) {
                Charset charsetD = x.d(xVar, null, 1, null);
                if (charsetD == null) {
                    xVar = x.f437g.c(xVar + "; charset=utf-8");
                } else {
                    charset = charsetD;
                }
            }
            byte[] bytes = str.getBytes(charset);
            t2.j.e(bytes, "(this as java.lang.String).getBytes(charset)");
            return f(bytes, xVar, 0, bytes.length);
        }

        public final C f(byte[] bArr, x xVar, int i3, int i4) {
            t2.j.f(bArr, "$this$toRequestBody");
            C2.c.i(bArr.length, i3, i4);
            return new b(bArr, xVar, i4, i3);
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final C c(x xVar, Q2.l lVar) {
        return f97a.a(xVar, lVar);
    }

    public static final C d(x xVar, String str) {
        return f97a.b(xVar, str);
    }

    public static final C e(x xVar, byte[] bArr) {
        return a.g(f97a, xVar, bArr, 0, 0, 12, null);
    }

    public abstract long a();

    public abstract x b();

    public boolean f() {
        return false;
    }

    public boolean g() {
        return false;
    }

    public abstract void h(Q2.j jVar);
}
