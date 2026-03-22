package p005b.p143g.p144a.p147m.p154u;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.util.Pools;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import p005b.p143g.p144a.C1557g;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;

/* renamed from: b.g.a.m.u.r */
/* loaded from: classes.dex */
public class C1676r {

    /* renamed from: a */
    public static final c f2397a = new c();

    /* renamed from: b */
    public static final InterfaceC1672n<Object, Object> f2398b = new a();

    /* renamed from: c */
    public final List<b<?, ?>> f2399c;

    /* renamed from: d */
    public final c f2400d;

    /* renamed from: e */
    public final Set<b<?, ?>> f2401e;

    /* renamed from: f */
    public final Pools.Pool<List<Throwable>> f2402f;

    /* renamed from: b.g.a.m.u.r$a */
    public static class a implements InterfaceC1672n<Object, Object> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
        /* renamed from: a */
        public boolean mo960a(@NonNull Object obj) {
            return false;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
        @Nullable
        /* renamed from: b */
        public InterfaceC1672n.a<Object> mo961b(@NonNull Object obj, int i2, int i3, @NonNull C1582n c1582n) {
            return null;
        }
    }

    /* renamed from: b.g.a.m.u.r$b */
    public static class b<Model, Data> {

        /* renamed from: a */
        public final Class<Model> f2403a;

        /* renamed from: b */
        public final Class<Data> f2404b;

        /* renamed from: c */
        public final InterfaceC1673o<? extends Model, ? extends Data> f2405c;

        public b(@NonNull Class<Model> cls, @NonNull Class<Data> cls2, @NonNull InterfaceC1673o<? extends Model, ? extends Data> interfaceC1673o) {
            this.f2403a = cls;
            this.f2404b = cls2;
            this.f2405c = interfaceC1673o;
        }
    }

    /* renamed from: b.g.a.m.u.r$c */
    public static class c {
    }

    public C1676r(@NonNull Pools.Pool<List<Throwable>> pool) {
        c cVar = f2397a;
        this.f2399c = new ArrayList();
        this.f2401e = new HashSet();
        this.f2402f = pool;
        this.f2400d = cVar;
    }

    @NonNull
    /* renamed from: a */
    public final <Model, Data> InterfaceC1672n<Model, Data> m978a(@NonNull b<?, ?> bVar) {
        InterfaceC1672n<Model, Data> interfaceC1672n = (InterfaceC1672n<Model, Data>) bVar.f2405c.mo963b(this);
        Objects.requireNonNull(interfaceC1672n, "Argument must not be null");
        return interfaceC1672n;
    }

    @NonNull
    /* renamed from: b */
    public synchronized <Model, Data> InterfaceC1672n<Model, Data> m979b(@NonNull Class<Model> cls, @NonNull Class<Data> cls2) {
        try {
            ArrayList arrayList = new ArrayList();
            boolean z = false;
            for (b<?, ?> bVar : this.f2399c) {
                if (this.f2401e.contains(bVar)) {
                    z = true;
                } else if (bVar.f2403a.isAssignableFrom(cls) && bVar.f2404b.isAssignableFrom(cls2)) {
                    this.f2401e.add(bVar);
                    arrayList.add(m978a(bVar));
                    this.f2401e.remove(bVar);
                }
            }
            if (arrayList.size() > 1) {
                c cVar = this.f2400d;
                Pools.Pool<List<Throwable>> pool = this.f2402f;
                Objects.requireNonNull(cVar);
                return new C1675q(arrayList, pool);
            }
            if (arrayList.size() == 1) {
                return (InterfaceC1672n) arrayList.get(0);
            }
            if (z) {
                return (InterfaceC1672n<Model, Data>) f2398b;
            }
            throw new C1557g.c((Class<?>) cls, (Class<?>) cls2);
        } catch (Throwable th) {
            this.f2401e.clear();
            throw th;
        }
    }

    @NonNull
    /* renamed from: c */
    public synchronized <Model> List<InterfaceC1672n<Model, ?>> m980c(@NonNull Class<Model> cls) {
        ArrayList arrayList;
        try {
            arrayList = new ArrayList();
            for (b<?, ?> bVar : this.f2399c) {
                if (!this.f2401e.contains(bVar) && bVar.f2403a.isAssignableFrom(cls)) {
                    this.f2401e.add(bVar);
                    InterfaceC1672n<? extends Object, ? extends Object> mo963b = bVar.f2405c.mo963b(this);
                    Objects.requireNonNull(mo963b, "Argument must not be null");
                    arrayList.add(mo963b);
                    this.f2401e.remove(bVar);
                }
            }
        } catch (Throwable th) {
            this.f2401e.clear();
            throw th;
        }
        return arrayList;
    }

    @NonNull
    /* renamed from: d */
    public synchronized List<Class<?>> m981d(@NonNull Class<?> cls) {
        ArrayList arrayList;
        arrayList = new ArrayList();
        for (b<?, ?> bVar : this.f2399c) {
            if (!arrayList.contains(bVar.f2404b) && bVar.f2403a.isAssignableFrom(cls)) {
                arrayList.add(bVar.f2404b);
            }
        }
        return arrayList;
    }
}
