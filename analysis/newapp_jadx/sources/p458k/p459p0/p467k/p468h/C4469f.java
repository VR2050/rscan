package p458k.p459p0.p467k.p468h;

import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import org.conscrypt.Conscrypt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.EnumC4377e0;
import p458k.p459p0.p467k.C4459c;
import p458k.p459p0.p467k.C4463g;

/* renamed from: k.p0.k.h.f */
/* loaded from: classes3.dex */
public final class C4469f implements InterfaceC4471h {
    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: a */
    public boolean mo5252a() {
        C4459c.a aVar = C4459c.f11970e;
        return C4459c.f11969d;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    @Nullable
    /* renamed from: b */
    public String mo5253b(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        if (mo5254c(sslSocket)) {
            return Conscrypt.getApplicationProtocol(sslSocket);
        }
        return null;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: c */
    public boolean mo5254c(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        return Conscrypt.isConscrypt(sslSocket);
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: d */
    public void mo5255d(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<? extends EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        if (mo5254c(sslSocket)) {
            Conscrypt.setUseSessionTickets(sslSocket, true);
            Object[] array = C4463g.f11988c.m5249a(protocols).toArray(new String[0]);
            if (array == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            Conscrypt.setApplicationProtocols(sslSocket, (String[]) array);
        }
    }
}
