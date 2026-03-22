package p458k.p459p0.p467k.p468h;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.EnumC4377e0;
import p458k.p459p0.p467k.C4458b;
import p458k.p459p0.p467k.C4463g;

/* renamed from: k.p0.k.h.d */
/* loaded from: classes3.dex */
public class C4467d implements InterfaceC4471h {

    /* renamed from: a */
    public final Method f11995a;

    /* renamed from: b */
    public final Method f11996b;

    /* renamed from: c */
    public final Method f11997c;

    /* renamed from: d */
    public final Method f11998d;

    /* renamed from: e */
    public final Class<? super SSLSocket> f11999e;

    public C4467d(@NotNull Class<? super SSLSocket> sslSocketClass) {
        Intrinsics.checkParameterIsNotNull(sslSocketClass, "sslSocketClass");
        this.f11999e = sslSocketClass;
        Method declaredMethod = sslSocketClass.getDeclaredMethod("setUseSessionTickets", Boolean.TYPE);
        Intrinsics.checkExpressionValueIsNotNull(declaredMethod, "sslSocketClass.getDeclar…:class.javaPrimitiveType)");
        this.f11995a = declaredMethod;
        this.f11996b = sslSocketClass.getMethod("setHostname", String.class);
        this.f11997c = sslSocketClass.getMethod("getAlpnSelectedProtocol", new Class[0]);
        this.f11998d = sslSocketClass.getMethod("setAlpnProtocols", byte[].class);
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: a */
    public boolean mo5252a() {
        C4458b.a aVar = C4458b.f11964f;
        return C4458b.f11963e;
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    @Nullable
    /* renamed from: b */
    public String mo5253b(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        if (!mo5254c(sslSocket)) {
            return null;
        }
        try {
            byte[] bArr = (byte[]) this.f11997c.invoke(sslSocket, new Object[0]);
            if (bArr == null) {
                return null;
            }
            Charset charset = StandardCharsets.UTF_8;
            Intrinsics.checkExpressionValueIsNotNull(charset, "StandardCharsets.UTF_8");
            return new String(bArr, charset);
        } catch (IllegalAccessException e2) {
            throw new AssertionError(e2);
        } catch (NullPointerException e3) {
            if (Intrinsics.areEqual(e3.getMessage(), "ssl == null")) {
                return null;
            }
            throw e3;
        } catch (InvocationTargetException e4) {
            throw new AssertionError(e4);
        }
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: c */
    public boolean mo5254c(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        return this.f11999e.isInstance(sslSocket);
    }

    @Override // p458k.p459p0.p467k.p468h.InterfaceC4471h
    /* renamed from: d */
    public void mo5255d(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<? extends EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        if (mo5254c(sslSocket)) {
            try {
                this.f11995a.invoke(sslSocket, Boolean.TRUE);
                if (str != null) {
                    this.f11996b.invoke(sslSocket, str);
                }
                this.f11998d.invoke(sslSocket, C4463g.f11988c.m5250b(protocols));
            } catch (IllegalAccessException e2) {
                throw new AssertionError(e2);
            } catch (InvocationTargetException e3) {
                throw new AssertionError(e3);
            }
        }
    }
}
