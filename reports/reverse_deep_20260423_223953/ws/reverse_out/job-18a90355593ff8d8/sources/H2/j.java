package H2;

import B2.B;
import B2.C;
import B2.D;
import B2.F;
import B2.u;
import B2.v;
import B2.z;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class j implements v {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f1092b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final z f1093a;

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public j(z zVar) {
        t2.j.f(zVar, "client");
        this.f1093a = zVar;
    }

    private final B b(D d3, String str) {
        String strD0;
        u uVarO;
        if (!this.f1093a.v() || (strD0 = D.d0(d3, "Location", null, 2, null)) == null || (uVarO = d3.y0().l().o(strD0)) == null) {
            return null;
        }
        if (!t2.j.b(uVarO.p(), d3.y0().l().p()) && !this.f1093a.w()) {
            return null;
        }
        B.a aVarI = d3.y0().i();
        if (f.b(str)) {
            int iA = d3.A();
            f fVar = f.f1078a;
            boolean z3 = fVar.d(str) || iA == 308 || iA == 307;
            if (!fVar.c(str) || iA == 308 || iA == 307) {
                aVarI.g(str, z3 ? d3.y0().a() : null);
            } else {
                aVarI.g("GET", null);
            }
            if (!z3) {
                aVarI.i("Transfer-Encoding");
                aVarI.i("Content-Length");
                aVarI.i("Content-Type");
            }
        }
        if (!C2.c.g(d3.y0().l(), uVarO)) {
            aVarI.i("Authorization");
        }
        return aVarI.l(uVarO).b();
    }

    private final B c(D d3, G2.c cVar) throws ProtocolException {
        G2.f fVarH;
        F fA = (cVar == null || (fVarH = cVar.h()) == null) ? null : fVarH.A();
        int iA = d3.A();
        String strH = d3.y0().h();
        if (iA != 307 && iA != 308) {
            if (iA == 401) {
                return this.f1093a.g().a(fA, d3);
            }
            if (iA == 421) {
                C cA = d3.y0().a();
                if ((cA != null && cA.g()) || cVar == null || !cVar.k()) {
                    return null;
                }
                cVar.h().y();
                return d3.y0();
            }
            if (iA == 503) {
                D dV0 = d3.v0();
                if ((dV0 == null || dV0.A() != 503) && g(d3, Integer.MAX_VALUE) == 0) {
                    return d3.y0();
                }
                return null;
            }
            if (iA == 407) {
                t2.j.c(fA);
                if (fA.b().type() == Proxy.Type.HTTP) {
                    return this.f1093a.H().a(fA, d3);
                }
                throw new ProtocolException("Received HTTP_PROXY_AUTH (407) code while not using proxy");
            }
            if (iA == 408) {
                if (!this.f1093a.K()) {
                    return null;
                }
                C cA2 = d3.y0().a();
                if (cA2 != null && cA2.g()) {
                    return null;
                }
                D dV02 = d3.v0();
                if ((dV02 == null || dV02.A() != 408) && g(d3, 0) <= 0) {
                    return d3.y0();
                }
                return null;
            }
            switch (iA) {
                case 300:
                case 301:
                case 302:
                case 303:
                    break;
                default:
                    return null;
            }
        }
        return b(d3, strH);
    }

    private final boolean d(IOException iOException, boolean z3) {
        if (iOException instanceof ProtocolException) {
            return false;
        }
        return iOException instanceof InterruptedIOException ? (iOException instanceof SocketTimeoutException) && !z3 : (((iOException instanceof SSLHandshakeException) && (iOException.getCause() instanceof CertificateException)) || (iOException instanceof SSLPeerUnverifiedException)) ? false : true;
    }

    private final boolean e(IOException iOException, G2.e eVar, B b3, boolean z3) {
        if (this.f1093a.K()) {
            return !(z3 && f(iOException, b3)) && d(iOException, z3) && eVar.z();
        }
        return false;
    }

    private final boolean f(IOException iOException, B b3) {
        C cA = b3.a();
        return (cA != null && cA.g()) || (iOException instanceof FileNotFoundException);
    }

    private final int g(D d3, int i3) {
        String strD0 = D.d0(d3, "Retry-After", null, 2, null);
        if (strD0 == null) {
            return i3;
        }
        if (!new z2.f("\\d+").a(strD0)) {
            return Integer.MAX_VALUE;
        }
        Integer numValueOf = Integer.valueOf(strD0);
        t2.j.e(numValueOf, "Integer.valueOf(header)");
        return numValueOf.intValue();
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0040, code lost:
    
        r7 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0045, code lost:
    
        r0 = r1.q();
        r6 = c(r7, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x004d, code lost:
    
        if (r6 != null) goto L21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x004f, code lost:
    
        if (r0 == null) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0055, code lost:
    
        if (r0.l() == false) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0057, code lost:
    
        r1.B();
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x005a, code lost:
    
        r1.k(false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x005d, code lost:
    
        return r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x005e, code lost:
    
        r0 = r6.a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0062, code lost:
    
        if (r0 == null) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0068, code lost:
    
        if (r0.g() == false) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x006a, code lost:
    
        r1.k(false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x006d, code lost:
    
        return r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x006e, code lost:
    
        r0 = r7.r();
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0072, code lost:
    
        if (r0 == null) goto L30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0074, code lost:
    
        C2.c.j(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0077, code lost:
    
        r8 = r8 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x007b, code lost:
    
        if (r8 > 20) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0098, code lost:
    
        throw new java.net.ProtocolException("Too many follow-up requests: " + r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x0026, code lost:
    
        if (r7 == null) goto L10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x0028, code lost:
    
        r0 = r0.u0().o(r7.u0().b(null).c()).c();
     */
    @Override // B2.v
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public B2.D a(B2.v.a r11) {
        /*
            Method dump skipped, instruction units count: 219
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: H2.j.a(B2.v$a):B2.D");
    }
}
