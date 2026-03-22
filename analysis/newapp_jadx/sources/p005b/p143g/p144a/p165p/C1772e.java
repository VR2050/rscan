package p005b.p143g.p144a.p165p;

import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import p005b.p143g.p144a.p147m.InterfaceC1584p;

/* renamed from: b.g.a.p.e */
/* loaded from: classes.dex */
public class C1772e {

    /* renamed from: a */
    public final List<String> f2645a = new ArrayList();

    /* renamed from: b */
    public final Map<String, List<a<?, ?>>> f2646b = new HashMap();

    /* renamed from: b.g.a.p.e$a */
    public static class a<T, R> {

        /* renamed from: a */
        public final Class<T> f2647a;

        /* renamed from: b */
        public final Class<R> f2648b;

        /* renamed from: c */
        public final InterfaceC1584p<T, R> f2649c;

        public a(@NonNull Class<T> cls, @NonNull Class<R> cls2, InterfaceC1584p<T, R> interfaceC1584p) {
            this.f2647a = cls;
            this.f2648b = cls2;
            this.f2649c = interfaceC1584p;
        }

        /* renamed from: a */
        public boolean m1068a(@NonNull Class<?> cls, @NonNull Class<?> cls2) {
            return this.f2647a.isAssignableFrom(cls) && cls2.isAssignableFrom(this.f2648b);
        }
    }

    @NonNull
    /* renamed from: a */
    public final synchronized List<a<?, ?>> m1066a(@NonNull String str) {
        List<a<?, ?>> list;
        if (!this.f2645a.contains(str)) {
            this.f2645a.add(str);
        }
        list = this.f2646b.get(str);
        if (list == null) {
            list = new ArrayList<>();
            this.f2646b.put(str, list);
        }
        return list;
    }

    @NonNull
    /* renamed from: b */
    public synchronized <T, R> List<Class<R>> m1067b(@NonNull Class<T> cls, @NonNull Class<R> cls2) {
        ArrayList arrayList;
        arrayList = new ArrayList();
        Iterator<String> it = this.f2645a.iterator();
        while (it.hasNext()) {
            List<a<?, ?>> list = this.f2646b.get(it.next());
            if (list != null) {
                for (a<?, ?> aVar : list) {
                    if (aVar.m1068a(cls, cls2) && !arrayList.contains(aVar.f2648b)) {
                        arrayList.add(aVar.f2648b);
                    }
                }
            }
        }
        return arrayList;
    }
}
