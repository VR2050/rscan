package p458k.p459p0.p467k.p468h;

import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.EnumC4377e0;
import p458k.p459p0.p467k.C4463g;

/* renamed from: k.p0.k.h.g */
/* loaded from: classes3.dex */
public final class C4470g implements InterfaceC4471h {

    /* renamed from: a */
    public boolean f12003a;

    /* renamed from: b */
    public InterfaceC4471h f12004b;

    /* renamed from: c */
    public final String f12005c;

    public C4470g(@NotNull String socketPackage) {
        Intrinsics.checkParameterIsNotNull(socketPackage, "socketPackage");
        this.f12005c = socketPackage;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: a */
    public boolean mo5252a() {
        return true;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    @Nullable
    /* renamed from: b */
    public String mo5253b(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        InterfaceC4471h m5256e = m5256e(sslSocket);
        if (m5256e != null) {
            return m5256e.mo5253b(sslSocket);
        }
        return null;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: c */
    public boolean mo5254c(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        String name = sslSocket.getClass().getName();
        Intrinsics.checkExpressionValueIsNotNull(name, "sslSocket.javaClass.name");
        return StringsKt__StringsJVMKt.startsWith$default(name, this.f12005c, false, 2, null);
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: d */
    public void mo5255d(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<? extends EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        InterfaceC4471h m5256e = m5256e(sslSocket);
        if (m5256e != null) {
            m5256e.mo5255d(sslSocket, str, protocols);
        }
    }

    /* renamed from: e */
    public final synchronized InterfaceC4471h m5256e(SSLSocket sSLSocket) {
        Class<?> cls;
        if (!this.f12003a) {
            try {
                cls = sSLSocket.getClass();
            } catch (Exception e2) {
                C4463g.a aVar = C4463g.f11988c;
                C4463g.f11986a.mo5236k("Failed to initialize DeferredSocketAdapter " + this.f12005c, 5, e2);
            }
            do {
                String name = cls.getName();
                if (!Intrinsics.areEqual(name, this.f12005c + ".OpenSSLSocketImpl")) {
                    cls = cls.getSuperclass();
                    Intrinsics.checkExpressionValueIsNotNull(cls, "possibleClass.superclass");
                } else {
                    this.f12004b = new C4467d(cls);
                    this.f12003a = true;
                }
            } while (cls != null);
            throw new AssertionError("No OpenSSLSocketImpl superclass of socket of type " + sSLSocket);
        }
        return this.f12004b;
    }
}
