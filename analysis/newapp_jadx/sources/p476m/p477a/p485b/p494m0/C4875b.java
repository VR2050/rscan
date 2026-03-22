package p476m.p477a.p485b.p494m0;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/* renamed from: m.a.b.m0.b */
/* loaded from: classes3.dex */
public final class C4875b<E> {

    /* renamed from: a */
    public final LinkedList<E> f12477a = new LinkedList<>();

    /* renamed from: b */
    public final Map<Class<?>, E> f12478b = new HashMap();

    /* renamed from: a */
    public C4875b<E> m5547a(E e2) {
        if (e2 == null) {
            return this;
        }
        m5548b(e2);
        this.f12477a.addLast(e2);
        return this;
    }

    /* renamed from: b */
    public final void m5548b(E e2) {
        E remove = this.f12478b.remove(e2.getClass());
        if (remove != null) {
            this.f12477a.remove(remove);
        }
        this.f12478b.put(e2.getClass(), e2);
    }
}
