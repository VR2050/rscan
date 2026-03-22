package p458k.p459p0.p462f;

import java.net.UnknownServiceException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.comparisons.ComparisonsKt__ComparisonsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4386j;
import p458k.C4392m;
import p458k.p459p0.C4401c;

/* renamed from: k.p0.f.b */
/* loaded from: classes3.dex */
public final class C4412b {

    /* renamed from: a */
    public int f11639a;

    /* renamed from: b */
    public boolean f11640b;

    /* renamed from: c */
    public boolean f11641c;

    /* renamed from: d */
    public final List<C4392m> f11642d;

    public C4412b(@NotNull List<C4392m> connectionSpecs) {
        Intrinsics.checkParameterIsNotNull(connectionSpecs, "connectionSpecs");
        this.f11642d = connectionSpecs;
    }

    @NotNull
    /* renamed from: a */
    public final C4392m m5082a(@NotNull SSLSocket sslSocket) {
        C4392m c4392m;
        boolean z;
        String[] cipherSuitesIntersection;
        String[] tlsVersionsIntersection;
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        int i2 = this.f11639a;
        int size = this.f11642d.size();
        while (true) {
            if (i2 >= size) {
                c4392m = null;
                break;
            }
            c4392m = this.f11642d.get(i2);
            if (c4392m.m4999b(sslSocket)) {
                this.f11639a = i2 + 1;
                break;
            }
            i2++;
        }
        if (c4392m == null) {
            StringBuilder m586H = C1499a.m586H("Unable to find acceptable protocols. isFallback=");
            m586H.append(this.f11641c);
            m586H.append(',');
            m586H.append(" modes=");
            m586H.append(this.f11642d);
            m586H.append(',');
            m586H.append(" supported protocols=");
            String[] enabledProtocols = sslSocket.getEnabledProtocols();
            if (enabledProtocols == null) {
                Intrinsics.throwNpe();
            }
            String arrays = Arrays.toString(enabledProtocols);
            Intrinsics.checkExpressionValueIsNotNull(arrays, "java.util.Arrays.toString(this)");
            m586H.append(arrays);
            throw new UnknownServiceException(m586H.toString());
        }
        int i3 = this.f11639a;
        int size2 = this.f11642d.size();
        while (true) {
            if (i3 >= size2) {
                z = false;
                break;
            }
            if (this.f11642d.get(i3).m4999b(sslSocket)) {
                z = true;
                break;
            }
            i3++;
        }
        this.f11640b = z;
        boolean z2 = this.f11641c;
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        if (c4392m.f11521g != null) {
            String[] enabledCipherSuites = sslSocket.getEnabledCipherSuites();
            Intrinsics.checkExpressionValueIsNotNull(enabledCipherSuites, "sslSocket.enabledCipherSuites");
            String[] strArr = c4392m.f11521g;
            C4386j.b bVar = C4386j.f11481s;
            Comparator<String> comparator = C4386j.f11463a;
            cipherSuitesIntersection = C4401c.m5031p(enabledCipherSuites, strArr, C4386j.f11463a);
        } else {
            cipherSuitesIntersection = sslSocket.getEnabledCipherSuites();
        }
        if (c4392m.f11522h != null) {
            String[] enabledProtocols2 = sslSocket.getEnabledProtocols();
            Intrinsics.checkExpressionValueIsNotNull(enabledProtocols2, "sslSocket.enabledProtocols");
            tlsVersionsIntersection = C4401c.m5031p(enabledProtocols2, c4392m.f11522h, ComparisonsKt__ComparisonsKt.naturalOrder());
        } else {
            tlsVersionsIntersection = sslSocket.getEnabledProtocols();
        }
        String[] indexOf = sslSocket.getSupportedCipherSuites();
        Intrinsics.checkExpressionValueIsNotNull(indexOf, "supportedCipherSuites");
        C4386j.b bVar2 = C4386j.f11481s;
        Comparator<String> comparator2 = C4386j.f11463a;
        Comparator<String> comparator3 = C4386j.f11463a;
        byte[] bArr = C4401c.f11556a;
        Intrinsics.checkParameterIsNotNull(indexOf, "$this$indexOf");
        Intrinsics.checkParameterIsNotNull("TLS_FALLBACK_SCSV", "value");
        Intrinsics.checkParameterIsNotNull(comparator3, "comparator");
        int length = indexOf.length;
        int i4 = 0;
        while (true) {
            if (i4 >= length) {
                i4 = -1;
                break;
            }
            if (((C4386j.a) comparator3).compare(indexOf[i4], "TLS_FALLBACK_SCSV") == 0) {
                break;
            }
            i4++;
        }
        if (z2 && i4 != -1) {
            Intrinsics.checkExpressionValueIsNotNull(cipherSuitesIntersection, "cipherSuitesIntersection");
            String value = indexOf[i4];
            Intrinsics.checkExpressionValueIsNotNull(value, "supportedCipherSuites[indexOfFallbackScsv]");
            Intrinsics.checkParameterIsNotNull(cipherSuitesIntersection, "$this$concat");
            Intrinsics.checkParameterIsNotNull(value, "value");
            Object[] copyOf = Arrays.copyOf(cipherSuitesIntersection, cipherSuitesIntersection.length + 1);
            Intrinsics.checkExpressionValueIsNotNull(copyOf, "java.util.Arrays.copyOf(this, newSize)");
            cipherSuitesIntersection = (String[]) copyOf;
            cipherSuitesIntersection[ArraysKt___ArraysKt.getLastIndex(cipherSuitesIntersection)] = value;
        }
        C4392m.a aVar = new C4392m.a(c4392m);
        Intrinsics.checkExpressionValueIsNotNull(cipherSuitesIntersection, "cipherSuitesIntersection");
        aVar.m5002b((String[]) Arrays.copyOf(cipherSuitesIntersection, cipherSuitesIntersection.length));
        Intrinsics.checkExpressionValueIsNotNull(tlsVersionsIntersection, "tlsVersionsIntersection");
        aVar.m5005e((String[]) Arrays.copyOf(tlsVersionsIntersection, tlsVersionsIntersection.length));
        C4392m m5001a = aVar.m5001a();
        if (m5001a.m5000c() != null) {
            sslSocket.setEnabledProtocols(m5001a.f11522h);
        }
        if (m5001a.m4998a() != null) {
            sslSocket.setEnabledCipherSuites(m5001a.f11521g);
        }
        return c4392m;
    }
}
