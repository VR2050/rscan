package p379c.p380a.p381a;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.a.d */
/* loaded from: classes2.dex */
public abstract class AbstractC2955d<T> extends AbstractC2966o {

    /* renamed from: a */
    public static final AtomicReferenceFieldUpdater f8100a = AtomicReferenceFieldUpdater.newUpdater(AbstractC2955d.class, Object.class, "_consensus");
    public volatile Object _consensus = C2954c.f8099a;

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p379c.p380a.p381a.AbstractC2966o
    @Nullable
    /* renamed from: a */
    public final Object mo3415a(@Nullable Object obj) {
        Object obj2 = this._consensus;
        Object obj3 = C2954c.f8099a;
        if (obj2 == obj3) {
            obj2 = mo3417c(obj);
            Object obj4 = this._consensus;
            if (obj4 != obj3) {
                obj2 = obj4;
            } else if (!f8100a.compareAndSet(this, obj3, obj2)) {
                obj2 = this._consensus;
            }
        }
        mo3416b(obj, obj2);
        return obj2;
    }

    /* renamed from: b */
    public abstract void mo3416b(T t, @Nullable Object obj);

    @Nullable
    /* renamed from: c */
    public abstract Object mo3417c(T t);
}
