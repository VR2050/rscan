package p476m.p496b.p500b;

import java.util.HashMap;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p496b.p500b.p501f.InterfaceC4931a;

/* renamed from: m.b.b.b */
/* loaded from: classes3.dex */
public class C4927b {

    /* renamed from: a */
    public final Map<Class<?>, AbstractC4926a<?, ?>> f12578a = new HashMap();

    public C4927b(InterfaceC4931a interfaceC4931a) {
    }

    /* renamed from: a */
    public AbstractC4926a<?, ?> m5603a(Class<? extends Object> cls) {
        AbstractC4926a<?, ?> abstractC4926a = this.f12578a.get(cls);
        if (abstractC4926a != null) {
            return abstractC4926a;
        }
        throw new C4928c(C1499a.m635u("No DAO registered for ", cls));
    }
}
