package p458k;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.SSLPeerUnverifiedException;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.conscrypt.EvpMdRef;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.p470m.AbstractC4476c;
import p474l.C4747i;

/* renamed from: k.h */
/* loaded from: classes3.dex */
public final class C4382h {

    /* renamed from: c */
    public final Set<b> f11452c;

    /* renamed from: d */
    @Nullable
    public final AbstractC4476c f11453d;

    /* renamed from: b */
    public static final a f11451b = new a(null);

    /* renamed from: a */
    @JvmField
    @NotNull
    public static final C4382h f11450a = new C4382h(CollectionsKt___CollectionsKt.toSet(new ArrayList()), null);

    /* renamed from: k.h$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        @JvmStatic
        @NotNull
        /* renamed from: a */
        public final String m4981a(@NotNull Certificate certificate) {
            Intrinsics.checkParameterIsNotNull(certificate, "certificate");
            return "sha256/" + m4982b((X509Certificate) certificate).mo5398a();
        }

        @NotNull
        /* renamed from: b */
        public final C4747i m4982b(@NotNull X509Certificate toSha256ByteString) {
            Intrinsics.checkParameterIsNotNull(toSha256ByteString, "$this$toSha256ByteString");
            C4747i.a aVar = C4747i.f12136e;
            PublicKey publicKey = toSha256ByteString.getPublicKey();
            Intrinsics.checkExpressionValueIsNotNull(publicKey, "publicKey");
            byte[] encoded = publicKey.getEncoded();
            Intrinsics.checkExpressionValueIsNotNull(encoded, "publicKey.encoded");
            return C4747i.a.m5409d(aVar, encoded, 0, 0, 3).mo5399b(EvpMdRef.SHA256.JCA_NAME);
        }
    }

    /* renamed from: k.h$b */
    public static final class b {
        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof b)) {
                return false;
            }
            Objects.requireNonNull((b) obj);
            return Intrinsics.areEqual((Object) null, (Object) null) && Intrinsics.areEqual((Object) null, (Object) null) && Intrinsics.areEqual((Object) null, (Object) null);
        }

        public int hashCode() {
            return 0;
        }

        @NotNull
        public String toString() {
            new StringBuilder().append((String) null);
            throw null;
        }
    }

    public C4382h(@NotNull Set<b> pins, @Nullable AbstractC4476c abstractC4476c) {
        Intrinsics.checkParameterIsNotNull(pins, "pins");
        this.f11452c = pins;
        this.f11453d = abstractC4476c;
    }

    /* renamed from: a */
    public final void m4980a(@NotNull String hostname, @NotNull Function0<? extends List<? extends X509Certificate>> cleanedPeerCertificatesFn) {
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        Intrinsics.checkParameterIsNotNull(cleanedPeerCertificatesFn, "cleanedPeerCertificatesFn");
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        List<b> emptyList = CollectionsKt__CollectionsKt.emptyList();
        for (b bVar : this.f11452c) {
            Objects.requireNonNull(bVar);
            Intrinsics.checkParameterIsNotNull(hostname, "hostname");
            if (StringsKt__StringsJVMKt.startsWith$default(null, "**.", false, 2, null)) {
                throw null;
            }
            if (StringsKt__StringsJVMKt.startsWith$default(null, "*.", false, 2, null)) {
                throw null;
            }
            if (Intrinsics.areEqual(hostname, (Object) null)) {
                if (emptyList.isEmpty()) {
                    emptyList = new ArrayList();
                }
                TypeIntrinsics.asMutableList(emptyList).add(bVar);
            }
        }
        if (emptyList.isEmpty()) {
            return;
        }
        List<? extends X509Certificate> invoke = cleanedPeerCertificatesFn.invoke();
        for (X509Certificate x509Certificate : invoke) {
            Iterator it = emptyList.iterator();
            if (it.hasNext()) {
                Objects.requireNonNull((b) it.next());
                throw null;
            }
        }
        StringBuilder m590L = C1499a.m590L("Certificate pinning failure!", "\n  Peer certificate chain:");
        for (X509Certificate toSha256ByteString : invoke) {
            m590L.append("\n    ");
            Intrinsics.checkParameterIsNotNull(toSha256ByteString, "certificate");
            if (!(toSha256ByteString instanceof X509Certificate)) {
                throw new IllegalArgumentException("Certificate pinning requires X509 certificates".toString());
            }
            StringBuilder sb = new StringBuilder();
            sb.append("sha256/");
            Intrinsics.checkParameterIsNotNull(toSha256ByteString, "$this$toSha256ByteString");
            C4747i.a aVar = C4747i.f12136e;
            PublicKey publicKey = toSha256ByteString.getPublicKey();
            Intrinsics.checkExpressionValueIsNotNull(publicKey, "publicKey");
            byte[] encoded = publicKey.getEncoded();
            Intrinsics.checkExpressionValueIsNotNull(encoded, "publicKey.encoded");
            sb.append(C4747i.a.m5409d(aVar, encoded, 0, 0, 3).mo5399b(EvpMdRef.SHA256.JCA_NAME).mo5398a());
            m590L.append(sb.toString());
            m590L.append(": ");
            Principal subjectDN = toSha256ByteString.getSubjectDN();
            Intrinsics.checkExpressionValueIsNotNull(subjectDN, "element.subjectDN");
            m590L.append(subjectDN.getName());
        }
        m590L.append("\n  Pinned certificates for ");
        m590L.append(hostname);
        m590L.append(":");
        for (b bVar2 : emptyList) {
            m590L.append("\n    ");
            m590L.append(bVar2);
        }
        String sb2 = m590L.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb2, "StringBuilder().apply(builderAction).toString()");
        throw new SSLPeerUnverifiedException(sb2);
    }

    public boolean equals(@Nullable Object obj) {
        if (obj instanceof C4382h) {
            C4382h c4382h = (C4382h) obj;
            if (Intrinsics.areEqual(c4382h.f11452c, this.f11452c) && Intrinsics.areEqual(c4382h.f11453d, this.f11453d)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        int hashCode = (this.f11452c.hashCode() + 1517) * 41;
        AbstractC4476c abstractC4476c = this.f11453d;
        return hashCode + (abstractC4476c != null ? abstractC4476c.hashCode() : 0);
    }
}
