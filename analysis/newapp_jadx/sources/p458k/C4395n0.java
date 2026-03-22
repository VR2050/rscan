package p458k;

import java.net.InetSocketAddress;
import java.net.Proxy;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: k.n0 */
/* loaded from: classes3.dex */
public final class C4395n0 {

    /* renamed from: a */
    @NotNull
    public final C4368a f11528a;

    /* renamed from: b */
    @NotNull
    public final Proxy f11529b;

    /* renamed from: c */
    @NotNull
    public final InetSocketAddress f11530c;

    public C4395n0(@NotNull C4368a address, @NotNull Proxy proxy, @NotNull InetSocketAddress socketAddress) {
        Intrinsics.checkParameterIsNotNull(address, "address");
        Intrinsics.checkParameterIsNotNull(proxy, "proxy");
        Intrinsics.checkParameterIsNotNull(socketAddress, "socketAddress");
        this.f11528a = address;
        this.f11529b = proxy;
        this.f11530c = socketAddress;
    }

    /* renamed from: a */
    public final boolean m5010a() {
        return this.f11528a.f11301f != null && this.f11529b.type() == Proxy.Type.HTTP;
    }

    public boolean equals(@Nullable Object obj) {
        if (obj instanceof C4395n0) {
            C4395n0 c4395n0 = (C4395n0) obj;
            if (Intrinsics.areEqual(c4395n0.f11528a, this.f11528a) && Intrinsics.areEqual(c4395n0.f11529b, this.f11529b) && Intrinsics.areEqual(c4395n0.f11530c, this.f11530c)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return this.f11530c.hashCode() + ((this.f11529b.hashCode() + ((this.f11528a.hashCode() + 527) * 31)) * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Route{");
        m586H.append(this.f11530c);
        m586H.append('}');
        return m586H.toString();
    }
}
