package p476m.p496b.p500b.p504i;

import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import p476m.p496b.p500b.AbstractC4926a;
import p476m.p496b.p500b.p504i.AbstractC4947a;

/* renamed from: m.b.b.i.b */
/* loaded from: classes3.dex */
public abstract class AbstractC4948b<T, Q extends AbstractC4947a<T>> {

    /* renamed from: a */
    public final String f12626a;

    /* renamed from: b */
    public final AbstractC4926a<T, ?> f12627b;

    /* renamed from: c */
    public final String[] f12628c;

    /* renamed from: d */
    public final Map<Long, WeakReference<Q>> f12629d = new HashMap();

    public AbstractC4948b(AbstractC4926a<T, ?> abstractC4926a, String str, String[] strArr) {
        this.f12627b = abstractC4926a;
        this.f12626a = str;
        this.f12628c = strArr;
    }

    /* renamed from: a */
    public void m5615a() {
        synchronized (this.f12629d) {
            Iterator<Map.Entry<Long, WeakReference<Q>>> it = this.f12629d.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getValue().get() == null) {
                    it.remove();
                }
            }
        }
    }
}
