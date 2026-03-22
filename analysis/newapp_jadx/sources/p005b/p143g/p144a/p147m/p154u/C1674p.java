package p005b.p143g.p144a.p147m.p154u;

import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* renamed from: b.g.a.m.u.p */
/* loaded from: classes.dex */
public class C1674p {

    /* renamed from: a */
    public final C1676r f2384a;

    /* renamed from: b */
    public final a f2385b;

    /* renamed from: b.g.a.m.u.p$a */
    public static class a {

        /* renamed from: a */
        public final Map<Class<?>, C5110a<?>> f2386a = new HashMap();

        /* renamed from: b.g.a.m.u.p$a$a, reason: collision with other inner class name */
        public static class C5110a<Model> {

            /* renamed from: a */
            public final List<InterfaceC1672n<Model, ?>> f2387a;

            public C5110a(List<InterfaceC1672n<Model, ?>> list) {
                this.f2387a = list;
            }
        }
    }

    public C1674p(@NonNull Pools.Pool<List<Throwable>> pool) {
        C1676r c1676r = new C1676r(pool);
        this.f2385b = new a();
        this.f2384a = c1676r;
    }
}
