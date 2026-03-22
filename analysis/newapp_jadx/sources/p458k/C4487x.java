package p458k;

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
import kotlin.LazyKt__LazyJVMKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.JvmName;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.PropertyReference1Impl;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KProperty;
import org.conscrypt.SSLNullSession;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;

/* renamed from: k.x */
/* loaded from: classes3.dex */
public final class C4487x {

    /* renamed from: a */
    public static final /* synthetic */ KProperty[] f12032a = {Reflection.property1(new PropertyReference1Impl(Reflection.getOrCreateKotlinClass(C4487x.class), "peerCertificates", "peerCertificates()Ljava/util/List;"))};

    /* renamed from: b */
    public static final a f12033b = new a(null);

    /* renamed from: c */
    @NotNull
    public final Lazy f12034c;

    /* renamed from: d */
    @NotNull
    public final EnumC4397o0 f12035d;

    /* renamed from: e */
    @NotNull
    public final C4386j f12036e;

    /* renamed from: f */
    @NotNull
    public final List<Certificate> f12037f;

    /* renamed from: k.x$a */
    public static final class a {

        /* renamed from: k.x$a$a, reason: collision with other inner class name */
        public static final class C5135a extends Lambda implements Function0<List<? extends Certificate>> {

            /* renamed from: c */
            public final /* synthetic */ List f12038c;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public C5135a(List list) {
                super(0);
                this.f12038c = list;
            }

            @Override // kotlin.jvm.functions.Function0
            public List<? extends Certificate> invoke() {
                return this.f12038c;
            }
        }

        /* renamed from: k.x$a$b */
        public static final class b extends Lambda implements Function0<List<? extends Certificate>> {

            /* renamed from: c */
            public final /* synthetic */ List f12039c;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public b(List list) {
                super(0);
                this.f12039c = list;
            }

            @Override // kotlin.jvm.functions.Function0
            public List<? extends Certificate> invoke() {
                return this.f12039c;
            }
        }

        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        @JvmStatic
        @JvmName(name = "get")
        @NotNull
        /* renamed from: a */
        public final C4487x m5274a(@NotNull SSLSession handshake) {
            List<Certificate> emptyList;
            Intrinsics.checkParameterIsNotNull(handshake, "$this$handshake");
            String cipherSuite = handshake.getCipherSuite();
            if (cipherSuite == null) {
                throw new IllegalStateException("cipherSuite == null".toString());
            }
            int hashCode = cipherSuite.hashCode();
            if (hashCode == 1019404634 ? cipherSuite.equals("TLS_NULL_WITH_NULL_NULL") : hashCode == 1208658923 && cipherSuite.equals(SSLNullSession.INVALID_CIPHER)) {
                throw new IOException(C1499a.m637w("cipherSuite == ", cipherSuite));
            }
            C4386j m4984b = C4386j.f11481s.m4984b(cipherSuite);
            String protocol = handshake.getProtocol();
            if (protocol == null) {
                throw new IllegalStateException("tlsVersion == null".toString());
            }
            if (Intrinsics.areEqual("NONE", protocol)) {
                throw new IOException("tlsVersion == NONE");
            }
            EnumC4397o0 m5012a = EnumC4397o0.f11537j.m5012a(protocol);
            try {
                emptyList = m5276c(handshake.getPeerCertificates());
            } catch (SSLPeerUnverifiedException unused) {
                emptyList = CollectionsKt__CollectionsKt.emptyList();
            }
            return new C4487x(m5012a, m4984b, m5276c(handshake.getLocalCertificates()), new b(emptyList));
        }

        @JvmStatic
        @NotNull
        /* renamed from: b */
        public final C4487x m5275b(@NotNull EnumC4397o0 tlsVersion, @NotNull C4386j cipherSuite, @NotNull List<? extends Certificate> peerCertificates, @NotNull List<? extends Certificate> localCertificates) {
            Intrinsics.checkParameterIsNotNull(tlsVersion, "tlsVersion");
            Intrinsics.checkParameterIsNotNull(cipherSuite, "cipherSuite");
            Intrinsics.checkParameterIsNotNull(peerCertificates, "peerCertificates");
            Intrinsics.checkParameterIsNotNull(localCertificates, "localCertificates");
            return new C4487x(tlsVersion, cipherSuite, C4401c.m5038w(localCertificates), new C5135a(C4401c.m5038w(peerCertificates)));
        }

        /* renamed from: c */
        public final List<Certificate> m5276c(@Nullable Certificate[] certificateArr) {
            return certificateArr != null ? C4401c.m5027l((Certificate[]) Arrays.copyOf(certificateArr, certificateArr.length)) : CollectionsKt__CollectionsKt.emptyList();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public C4487x(@NotNull EnumC4397o0 tlsVersion, @NotNull C4386j cipherSuite, @NotNull List<? extends Certificate> localCertificates, @NotNull Function0<? extends List<? extends Certificate>> peerCertificatesFn) {
        Intrinsics.checkParameterIsNotNull(tlsVersion, "tlsVersion");
        Intrinsics.checkParameterIsNotNull(cipherSuite, "cipherSuite");
        Intrinsics.checkParameterIsNotNull(localCertificates, "localCertificates");
        Intrinsics.checkParameterIsNotNull(peerCertificatesFn, "peerCertificatesFn");
        this.f12035d = tlsVersion;
        this.f12036e = cipherSuite;
        this.f12037f = localCertificates;
        this.f12034c = LazyKt__LazyJVMKt.lazy(peerCertificatesFn);
    }

    /* renamed from: a */
    public final String m5272a(@NotNull Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate).getSubjectDN().toString();
        }
        String type = certificate.getType();
        Intrinsics.checkExpressionValueIsNotNull(type, "type");
        return type;
    }

    @JvmName(name = "peerCertificates")
    @NotNull
    /* renamed from: b */
    public final List<Certificate> m5273b() {
        Lazy lazy = this.f12034c;
        KProperty kProperty = f12032a[0];
        return (List) lazy.getValue();
    }

    public boolean equals(@Nullable Object obj) {
        if (obj instanceof C4487x) {
            C4487x c4487x = (C4487x) obj;
            if (c4487x.f12035d == this.f12035d && Intrinsics.areEqual(c4487x.f12036e, this.f12036e) && Intrinsics.areEqual(c4487x.m5273b(), m5273b()) && Intrinsics.areEqual(c4487x.f12037f, this.f12037f)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return this.f12037f.hashCode() + ((m5273b().hashCode() + ((this.f12036e.hashCode() + ((this.f12035d.hashCode() + 527) * 31)) * 31)) * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m590L = C1499a.m590L("Handshake{", "tlsVersion=");
        m590L.append(this.f12035d);
        m590L.append(' ');
        m590L.append("cipherSuite=");
        m590L.append(this.f12036e);
        m590L.append(' ');
        m590L.append("peerCertificates=");
        List<Certificate> m5273b = m5273b();
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(m5273b, 10));
        Iterator<T> it = m5273b.iterator();
        while (it.hasNext()) {
            arrayList.add(m5272a((Certificate) it.next()));
        }
        m590L.append(arrayList);
        m590L.append(' ');
        m590L.append("localCertificates=");
        List<Certificate> list = this.f12037f;
        ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(list, 10));
        Iterator<T> it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList2.add(m5272a((Certificate) it2.next()));
        }
        m590L.append(arrayList2);
        m590L.append('}');
        return m590L.toString();
    }
}
