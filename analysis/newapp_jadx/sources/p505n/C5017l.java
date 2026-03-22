package p505n;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

/* renamed from: n.l */
/* loaded from: classes3.dex */
public final class C5017l {

    /* renamed from: a */
    public final Method f12833a;

    /* renamed from: b */
    public final List<?> f12834b;

    public C5017l(Method method, List<?> list) {
        this.f12833a = method;
        this.f12834b = Collections.unmodifiableList(list);
    }

    public String toString() {
        return String.format("%s.%s() %s", this.f12833a.getDeclaringClass().getName(), this.f12833a.getName(), this.f12834b);
    }
}
