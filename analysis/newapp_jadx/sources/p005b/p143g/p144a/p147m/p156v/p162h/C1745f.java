package p005b.p143g.p144a.p147m.p156v.p162h;

import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* renamed from: b.g.a.m.v.h.f */
/* loaded from: classes.dex */
public class C1745f {

    /* renamed from: a */
    public final List<a<?, ?>> f2602a = new ArrayList();

    /* renamed from: b.g.a.m.v.h.f$a */
    public static final class a<Z, R> {

        /* renamed from: a */
        public final Class<Z> f2603a;

        /* renamed from: b */
        public final Class<R> f2604b;

        /* renamed from: c */
        public final InterfaceC1744e<Z, R> f2605c;

        public a(@NonNull Class<Z> cls, @NonNull Class<R> cls2, @NonNull InterfaceC1744e<Z, R> interfaceC1744e) {
            this.f2603a = cls;
            this.f2604b = cls2;
            this.f2605c = interfaceC1744e;
        }

        /* renamed from: a */
        public boolean m1039a(@NonNull Class<?> cls, @NonNull Class<?> cls2) {
            return this.f2603a.isAssignableFrom(cls) && cls2.isAssignableFrom(this.f2604b);
        }
    }

    @NonNull
    /* renamed from: a */
    public synchronized <Z, R> List<Class<R>> m1038a(@NonNull Class<Z> cls, @NonNull Class<R> cls2) {
        ArrayList arrayList = new ArrayList();
        if (cls2.isAssignableFrom(cls)) {
            arrayList.add(cls2);
            return arrayList;
        }
        Iterator<a<?, ?>> it = this.f2602a.iterator();
        while (it.hasNext()) {
            if (it.next().m1039a(cls, cls2)) {
                arrayList.add(cls2);
            }
        }
        return arrayList;
    }
}
