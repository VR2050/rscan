package B2;

import Q2.l;
import i2.AbstractC0586n;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SSLPeerUnverifiedException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: renamed from: B2.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0169g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Set f218a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final O2.c f219b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final b f217d = new b(null);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final C0169g f216c = new a().a();

    /* JADX INFO: renamed from: B2.g$a */
    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final List f220a = new ArrayList();

        /* JADX WARN: Multi-variable type inference failed */
        public final C0169g a() {
            return new C0169g(AbstractC0586n.W(this.f220a), null, 2, 0 == true ? 1 : 0);
        }
    }

    /* JADX INFO: renamed from: B2.g$b */
    public static final class b {
        private b() {
        }

        public final String a(Certificate certificate) {
            t2.j.f(certificate, "certificate");
            if (!(certificate instanceof X509Certificate)) {
                throw new IllegalArgumentException("Certificate pinning requires X509 certificates");
            }
            return "sha256/" + b((X509Certificate) certificate).a();
        }

        public final Q2.l b(X509Certificate x509Certificate) {
            t2.j.f(x509Certificate, "$this$sha256Hash");
            l.a aVar = Q2.l.f2556f;
            PublicKey publicKey = x509Certificate.getPublicKey();
            t2.j.e(publicKey, "publicKey");
            byte[] encoded = publicKey.getEncoded();
            t2.j.e(encoded, "publicKey.encoded");
            return l.a.h(aVar, encoded, 0, 0, 3, null).u();
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX INFO: renamed from: B2.g$c */
    static final class c extends t2.k implements InterfaceC0688a {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ List f222d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f223e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        c(List list, String str) {
            super(0);
            this.f222d = list;
            this.f223e = str;
        }

        @Override // s2.InterfaceC0688a
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final List a() {
            List<Certificate> listA;
            O2.c cVarD = C0169g.this.d();
            if (cVarD == null || (listA = cVarD.a(this.f222d, this.f223e)) == null) {
                listA = this.f222d;
            }
            ArrayList arrayList = new ArrayList(AbstractC0586n.o(listA, 10));
            for (Certificate certificate : listA) {
                if (certificate == null) {
                    throw new NullPointerException("null cannot be cast to non-null type java.security.cert.X509Certificate");
                }
                arrayList.add((X509Certificate) certificate);
            }
            return arrayList;
        }
    }

    public C0169g(Set set, O2.c cVar) {
        t2.j.f(set, "pins");
        this.f218a = set;
        this.f219b = cVar;
    }

    public final void a(String str, List list) {
        t2.j.f(str, "hostname");
        t2.j.f(list, "peerCertificates");
        b(str, new c(list, str));
    }

    public final void b(String str, InterfaceC0688a interfaceC0688a) throws SSLPeerUnverifiedException {
        t2.j.f(str, "hostname");
        t2.j.f(interfaceC0688a, "cleanedPeerCertificatesFn");
        List listC = c(str);
        if (listC.isEmpty()) {
            return;
        }
        List<X509Certificate> list = (List) interfaceC0688a.a();
        for (X509Certificate x509Certificate : list) {
            Iterator it = listC.iterator();
            if (it.hasNext()) {
                androidx.activity.result.d.a(it.next());
                throw null;
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Certificate pinning failure!");
        sb.append("\n  Peer certificate chain:");
        for (X509Certificate x509Certificate2 : list) {
            sb.append("\n    ");
            sb.append(f217d.a(x509Certificate2));
            sb.append(": ");
            Principal subjectDN = x509Certificate2.getSubjectDN();
            t2.j.e(subjectDN, "element.subjectDN");
            sb.append(subjectDN.getName());
        }
        sb.append("\n  Pinned certificates for ");
        sb.append(str);
        sb.append(":");
        Iterator it2 = listC.iterator();
        while (it2.hasNext()) {
            androidx.activity.result.d.a(it2.next());
            sb.append("\n    ");
            sb.append((Object) null);
        }
        String string = sb.toString();
        t2.j.e(string, "StringBuilder().apply(builderAction).toString()");
        throw new SSLPeerUnverifiedException(string);
    }

    public final List c(String str) {
        t2.j.f(str, "hostname");
        Set set = this.f218a;
        List listG = AbstractC0586n.g();
        Iterator it = set.iterator();
        if (!it.hasNext()) {
            return listG;
        }
        androidx.activity.result.d.a(it.next());
        throw null;
    }

    public final O2.c d() {
        return this.f219b;
    }

    public final C0169g e(O2.c cVar) {
        t2.j.f(cVar, "certificateChainCleaner");
        return t2.j.b(this.f219b, cVar) ? this : new C0169g(this.f218a, cVar);
    }

    public boolean equals(Object obj) {
        if (obj instanceof C0169g) {
            C0169g c0169g = (C0169g) obj;
            if (t2.j.b(c0169g.f218a, this.f218a) && t2.j.b(c0169g.f219b, this.f219b)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        int iHashCode = (1517 + this.f218a.hashCode()) * 41;
        O2.c cVar = this.f219b;
        return iHashCode + (cVar != null ? cVar.hashCode() : 0);
    }

    public /* synthetic */ C0169g(Set set, O2.c cVar, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(set, (i3 & 2) != 0 ? null : cVar);
    }
}
