package B2;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import kotlin.jvm.internal.DefaultConstructorMarker;
import q2.AbstractC0663a;

/* JADX INFO: loaded from: classes.dex */
public abstract class E implements Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f131b = new a(null);

    public static final class a {

        /* JADX INFO: renamed from: B2.E$a$a, reason: collision with other inner class name */
        public static final class C0003a extends E {

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ Q2.k f132c;

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            final /* synthetic */ x f133d;

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            final /* synthetic */ long f134e;

            C0003a(Q2.k kVar, x xVar, long j3) {
                this.f132c = kVar;
                this.f133d = xVar;
                this.f134e = j3;
            }

            @Override // B2.E
            public long r() {
                return this.f134e;
            }

            @Override // B2.E
            public x v() {
                return this.f133d;
            }

            @Override // B2.E
            public Q2.k y() {
                return this.f132c;
            }
        }

        private a() {
        }

        public static /* synthetic */ E d(a aVar, byte[] bArr, x xVar, int i3, Object obj) {
            if ((i3 & 1) != 0) {
                xVar = null;
            }
            return aVar.c(bArr, xVar);
        }

        public final E a(x xVar, long j3, Q2.k kVar) {
            t2.j.f(kVar, "content");
            return b(kVar, xVar, j3);
        }

        public final E b(Q2.k kVar, x xVar, long j3) {
            t2.j.f(kVar, "$this$asResponseBody");
            return new C0003a(kVar, xVar, j3);
        }

        public final E c(byte[] bArr, x xVar) {
            t2.j.f(bArr, "$this$toResponseBody");
            return b(new Q2.i().Q(bArr), xVar, bArr.length);
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    private final Charset p() {
        Charset charsetC;
        x xVarV = v();
        return (xVarV == null || (charsetC = xVarV.c(z2.d.f10544b)) == null) ? z2.d.f10544b : charsetC;
    }

    public static final E x(x xVar, long j3, Q2.k kVar) {
        return f131b.a(xVar, j3, kVar);
    }

    public final String A() throws IOException {
        Q2.k kVarY = y();
        try {
            String strP0 = kVarY.p0(C2.c.G(kVarY, p()));
            AbstractC0663a.a(kVarY, null);
            return strP0;
        } finally {
        }
    }

    public final InputStream b() {
        return y().q0();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        C2.c.j(y());
    }

    public final byte[] i() throws IOException {
        long jR = r();
        if (jR > Integer.MAX_VALUE) {
            throw new IOException("Cannot buffer entire body for content length: " + jR);
        }
        Q2.k kVarY = y();
        try {
            byte[] bArrI = kVarY.I();
            AbstractC0663a.a(kVarY, null);
            int length = bArrI.length;
            if (jR == -1 || jR == length) {
                return bArrI;
            }
            throw new IOException("Content-Length (" + jR + ") and stream length (" + length + ") disagree");
        } finally {
        }
    }

    public abstract long r();

    public abstract x v();

    public abstract Q2.k y();
}
