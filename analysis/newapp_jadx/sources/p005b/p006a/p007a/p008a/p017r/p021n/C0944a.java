package p005b.p006a.p007a.p008a.p017r.p021n;

import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.C0925i;
import p005b.p006a.p007a.p008a.p017r.C0926j;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p018k.C0927a;
import p005b.p006a.p007a.p008a.p017r.p018k.C0933g;
import p005b.p006a.p007a.p008a.p017r.p020m.C0941b;
import p005b.p006a.p007a.p008a.p017r.p020m.C0943d;
import p379c.p380a.p383b2.InterfaceC3006b;

/* renamed from: b.a.a.a.r.n.a */
/* loaded from: classes2.dex */
public final class C0944a {

    /* renamed from: a */
    @NotNull
    public final Lazy f471a = LazyKt__LazyJVMKt.lazy(a.f472c);

    /* renamed from: b.a.a.a.r.n.a$a */
    public static final class a extends Lambda implements Function0<InterfaceC0921e> {

        /* renamed from: c */
        public static final a f472c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public InterfaceC0921e invoke() {
            C0926j c0926j = C0926j.f441a;
            C0926j c0926j2 = C0926j.f442b;
            String baseUrl = C0925i.f437a.m270b();
            Objects.requireNonNull(c0926j2);
            Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
            return (InterfaceC0921e) c0926j2.m271a(baseUrl, new C0933g(null), new C0927a(), c0926j2.m272b(40L, new C0943d(), new C0941b())).m5687b(InterfaceC0921e.class);
        }
    }

    /* renamed from: a */
    public final InterfaceC0921e m287a() {
        return (InterfaceC0921e) this.f471a.getValue();
    }

    @NotNull
    /* renamed from: b */
    public final InterfaceC3006b<UserInfoBean> m288b() {
        return m287a().m233C();
    }
}
