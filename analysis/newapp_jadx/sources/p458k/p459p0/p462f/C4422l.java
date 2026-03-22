package p458k.p459p0.p462f;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.AbstractC4485v;
import p458k.C4368a;
import p458k.C4395n0;
import p458k.C4489z;
import p458k.InterfaceC4378f;
import p458k.p459p0.C4401c;

/* renamed from: k.p0.f.l */
/* loaded from: classes3.dex */
public final class C4422l {

    /* renamed from: a */
    public List<? extends Proxy> f11702a;

    /* renamed from: b */
    public int f11703b;

    /* renamed from: c */
    public List<? extends InetSocketAddress> f11704c;

    /* renamed from: d */
    public final List<C4395n0> f11705d;

    /* renamed from: e */
    public final C4368a f11706e;

    /* renamed from: f */
    public final C4420j f11707f;

    /* renamed from: g */
    public final InterfaceC4378f f11708g;

    /* renamed from: h */
    public final AbstractC4485v f11709h;

    /* renamed from: k.p0.f.l$a */
    public static final class a {

        /* renamed from: a */
        public int f11710a;

        /* renamed from: b */
        @NotNull
        public final List<C4395n0> f11711b;

        public a(@NotNull List<C4395n0> routes) {
            Intrinsics.checkParameterIsNotNull(routes, "routes");
            this.f11711b = routes;
        }

        /* renamed from: a */
        public final boolean m5115a() {
            return this.f11710a < this.f11711b.size();
        }
    }

    public C4422l(@NotNull C4368a address, @NotNull C4420j routeDatabase, @NotNull InterfaceC4378f call, @NotNull AbstractC4485v eventListener) {
        List<? extends Proxy> proxies;
        Intrinsics.checkParameterIsNotNull(address, "address");
        Intrinsics.checkParameterIsNotNull(routeDatabase, "routeDatabase");
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(eventListener, "eventListener");
        this.f11706e = address;
        this.f11707f = routeDatabase;
        this.f11708g = call;
        this.f11709h = eventListener;
        this.f11702a = CollectionsKt__CollectionsKt.emptyList();
        this.f11704c = CollectionsKt__CollectionsKt.emptyList();
        this.f11705d = new ArrayList();
        C4489z url = address.f11296a;
        Proxy proxy = address.f11305j;
        Objects.requireNonNull(eventListener);
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(url, "url");
        if (proxy != null) {
            proxies = CollectionsKt__CollectionsJVMKt.listOf(proxy);
        } else {
            List<Proxy> select = address.f11306k.select(url.m5298h());
            proxies = (select == null || !(select.isEmpty() ^ true)) ? C4401c.m5027l(Proxy.NO_PROXY) : C4401c.m5038w(select);
        }
        this.f11702a = proxies;
        this.f11703b = 0;
        Objects.requireNonNull(eventListener);
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(url, "url");
        Intrinsics.checkParameterIsNotNull(proxies, "proxies");
    }

    /* renamed from: a */
    public final boolean m5113a() {
        return m5114b() || (this.f11705d.isEmpty() ^ true);
    }

    /* renamed from: b */
    public final boolean m5114b() {
        return this.f11703b < this.f11702a.size();
    }
}
