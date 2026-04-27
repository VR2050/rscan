package B2;

import h2.AbstractC0558d;
import i2.AbstractC0586n;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import kotlin.Lazy;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class s {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f402e = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Lazy f403a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G f404b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0171i f405c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f406d;

    public static final class a {

        /* JADX INFO: renamed from: B2.s$a$a, reason: collision with other inner class name */
        static final class C0009a extends t2.k implements InterfaceC0688a {

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ List f407c;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            C0009a(List list) {
                super(0);
                this.f407c = list;
            }

            @Override // s2.InterfaceC0688a
            /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
            public final List a() {
                return this.f407c;
            }
        }

        static final class b extends t2.k implements InterfaceC0688a {

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ List f408c;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            b(List list) {
                super(0);
                this.f408c = list;
            }

            @Override // s2.InterfaceC0688a
            /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
            public final List a() {
                return this.f408c;
            }
        }

        private a() {
        }

        private final List c(Certificate[] certificateArr) {
            return certificateArr != null ? C2.c.t((Certificate[]) Arrays.copyOf(certificateArr, certificateArr.length)) : AbstractC0586n.g();
        }

        public final s a(G g3, C0171i c0171i, List list, List list2) {
            t2.j.f(g3, "tlsVersion");
            t2.j.f(c0171i, "cipherSuite");
            t2.j.f(list, "peerCertificates");
            t2.j.f(list2, "localCertificates");
            return new s(g3, c0171i, C2.c.R(list2), new C0009a(C2.c.R(list)));
        }

        public final s b(SSLSession sSLSession) throws IOException {
            List listG;
            t2.j.f(sSLSession, "$this$handshake");
            String cipherSuite = sSLSession.getCipherSuite();
            if (cipherSuite == null) {
                throw new IllegalStateException("cipherSuite == null");
            }
            int iHashCode = cipherSuite.hashCode();
            if (iHashCode == 1019404634 ? cipherSuite.equals("TLS_NULL_WITH_NULL_NULL") : iHashCode == 1208658923 && cipherSuite.equals("SSL_NULL_WITH_NULL_NULL")) {
                throw new IOException("cipherSuite == " + cipherSuite);
            }
            C0171i c0171iB = C0171i.f333s1.b(cipherSuite);
            String protocol = sSLSession.getProtocol();
            if (protocol == null) {
                throw new IllegalStateException("tlsVersion == null");
            }
            if (t2.j.b("NONE", protocol)) {
                throw new IOException("tlsVersion == NONE");
            }
            G gA = G.f144i.a(protocol);
            try {
                listG = c(sSLSession.getPeerCertificates());
            } catch (SSLPeerUnverifiedException unused) {
                listG = AbstractC0586n.g();
            }
            return new s(gA, c0171iB, c(sSLSession.getLocalCertificates()), new b(listG));
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static final class b extends t2.k implements InterfaceC0688a {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ InterfaceC0688a f409c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        b(InterfaceC0688a interfaceC0688a) {
            super(0);
            this.f409c = interfaceC0688a;
        }

        @Override // s2.InterfaceC0688a
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final List a() {
            try {
                return (List) this.f409c.a();
            } catch (SSLPeerUnverifiedException unused) {
                return AbstractC0586n.g();
            }
        }
    }

    public s(G g3, C0171i c0171i, List list, InterfaceC0688a interfaceC0688a) {
        t2.j.f(g3, "tlsVersion");
        t2.j.f(c0171i, "cipherSuite");
        t2.j.f(list, "localCertificates");
        t2.j.f(interfaceC0688a, "peerCertificatesFn");
        this.f404b = g3;
        this.f405c = c0171i;
        this.f406d = list;
        this.f403a = AbstractC0558d.b(new b(interfaceC0688a));
    }

    private final String b(Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate).getSubjectDN().toString();
        }
        String type = certificate.getType();
        t2.j.e(type, "type");
        return type;
    }

    public final C0171i a() {
        return this.f405c;
    }

    public final List c() {
        return this.f406d;
    }

    public final List d() {
        return (List) this.f403a.getValue();
    }

    public final G e() {
        return this.f404b;
    }

    public boolean equals(Object obj) {
        if (obj instanceof s) {
            s sVar = (s) obj;
            if (sVar.f404b == this.f404b && t2.j.b(sVar.f405c, this.f405c) && t2.j.b(sVar.d(), d()) && t2.j.b(sVar.f406d, this.f406d)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return ((((((527 + this.f404b.hashCode()) * 31) + this.f405c.hashCode()) * 31) + d().hashCode()) * 31) + this.f406d.hashCode();
    }

    public String toString() {
        List listD = d();
        ArrayList arrayList = new ArrayList(AbstractC0586n.o(listD, 10));
        Iterator it = listD.iterator();
        while (it.hasNext()) {
            arrayList.add(b((Certificate) it.next()));
        }
        String string = arrayList.toString();
        StringBuilder sb = new StringBuilder();
        sb.append("Handshake{");
        sb.append("tlsVersion=");
        sb.append(this.f404b);
        sb.append(' ');
        sb.append("cipherSuite=");
        sb.append(this.f405c);
        sb.append(' ');
        sb.append("peerCertificates=");
        sb.append(string);
        sb.append(' ');
        sb.append("localCertificates=");
        List list = this.f406d;
        ArrayList arrayList2 = new ArrayList(AbstractC0586n.o(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList2.add(b((Certificate) it2.next()));
        }
        sb.append(arrayList2);
        sb.append('}');
        return sb.toString();
    }
}
