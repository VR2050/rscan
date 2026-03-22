package p458k.p459p0.p467k.p468h;

import android.net.SSLCertificateSocketFactory;
import android.os.Build;
import java.util.List;
import javax.net.SocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.EnumC4377e0;
import p458k.p459p0.p467k.C4458b;
import p458k.p459p0.p467k.C4463g;

/* renamed from: k.p0.k.h.b */
/* loaded from: classes3.dex */
public final class C4465b implements InterfaceC4471h {

    /* renamed from: a */
    public final SSLCertificateSocketFactory f11991a;

    public C4465b() {
        SocketFactory socketFactory = SSLCertificateSocketFactory.getDefault(10000);
        if (socketFactory == null) {
            throw new TypeCastException("null cannot be cast to non-null type android.net.SSLCertificateSocketFactory");
        }
        this.f11991a = (SSLCertificateSocketFactory) socketFactory;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: a */
    public boolean mo5252a() {
        C4458b.a aVar = C4458b.f11964f;
        return C4458b.f11962d && Build.VERSION.SDK_INT >= 29;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    @Nullable
    /* renamed from: b */
    public String mo5253b(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        String applicationProtocol = sslSocket.getApplicationProtocol();
        if (applicationProtocol == null || Intrinsics.areEqual(applicationProtocol, "")) {
            return null;
        }
        return applicationProtocol;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: c */
    public boolean mo5254c(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        String name = sslSocket.getClass().getName();
        Intrinsics.checkExpressionValueIsNotNull(name, "sslSocket.javaClass.name");
        return StringsKt__StringsJVMKt.startsWith$default(name, "com.android.org.conscrypt", false, 2, null);
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: d */
    public void mo5255d(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<? extends EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        this.f11991a.setUseSessionTickets(sslSocket, true);
        SSLParameters sslParameters = sslSocket.getSSLParameters();
        Intrinsics.checkExpressionValueIsNotNull(sslParameters, "sslParameters");
        Object[] array = C4463g.f11988c.m5249a(protocols).toArray(new String[0]);
        if (array == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
        }
        sslParameters.setApplicationProtocols((String[]) array);
        sslSocket.setSSLParameters(sslParameters);
    }
}
