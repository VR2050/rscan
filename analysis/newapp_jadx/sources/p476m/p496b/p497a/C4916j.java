package p476m.p496b.p497a;

import java.util.ArrayList;
import java.util.List;

/* renamed from: m.b.a.j */
/* loaded from: classes3.dex */
public final class C4916j {

    /* renamed from: a */
    public static final List<C4916j> f12544a = new ArrayList();

    /* renamed from: b */
    public Object f12545b;

    /* renamed from: c */
    public C4923q f12546c;

    /* renamed from: d */
    public C4916j f12547d;

    public C4916j(Object obj, C4923q c4923q) {
        this.f12545b = obj;
        this.f12546c = c4923q;
    }

    /* renamed from: a */
    public static C4916j m5584a(C4923q c4923q, Object obj) {
        List<C4916j> list = f12544a;
        synchronized (list) {
            int size = list.size();
            if (size <= 0) {
                return new C4916j(obj, c4923q);
            }
            C4916j remove = list.remove(size - 1);
            remove.f12545b = obj;
            remove.f12546c = c4923q;
            remove.f12547d = null;
            return remove;
        }
    }
}
