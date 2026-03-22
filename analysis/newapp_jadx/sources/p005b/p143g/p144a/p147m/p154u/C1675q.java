package p005b.p143g.p144a.p147m.p154u;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.util.Pools;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p150t.C1650r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;

/* renamed from: b.g.a.m.u.q */
/* loaded from: classes.dex */
public class C1675q<Model, Data> implements InterfaceC1672n<Model, Data> {

    /* renamed from: a */
    public final List<InterfaceC1672n<Model, Data>> f2388a;

    /* renamed from: b */
    public final Pools.Pool<List<Throwable>> f2389b;

    /* renamed from: b.g.a.m.u.q$a */
    public static class a<Data> implements InterfaceC1590d<Data>, InterfaceC1590d.a<Data> {

        /* renamed from: c */
        public final List<InterfaceC1590d<Data>> f2390c;

        /* renamed from: e */
        public final Pools.Pool<List<Throwable>> f2391e;

        /* renamed from: f */
        public int f2392f;

        /* renamed from: g */
        public EnumC1556f f2393g;

        /* renamed from: h */
        public InterfaceC1590d.a<? super Data> f2394h;

        /* renamed from: i */
        @Nullable
        public List<Throwable> f2395i;

        /* renamed from: j */
        public boolean f2396j;

        public a(@NonNull List<InterfaceC1590d<Data>> list, @NonNull Pools.Pool<List<Throwable>> pool) {
            this.f2391e = pool;
            if (list.isEmpty()) {
                throw new IllegalArgumentException("Must not be empty.");
            }
            this.f2390c = list;
            this.f2392f = 0;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<Data> mo832a() {
            return this.f2390c.get(0).mo832a();
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: b */
        public void mo835b() {
            List<Throwable> list = this.f2395i;
            if (list != null) {
                this.f2391e.release(list);
            }
            this.f2395i = null;
            Iterator<InterfaceC1590d<Data>> it = this.f2390c.iterator();
            while (it.hasNext()) {
                it.next().mo835b();
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
        /* renamed from: c */
        public void mo839c(@NonNull Exception exc) {
            List<Throwable> list = this.f2395i;
            Objects.requireNonNull(list, "Argument must not be null");
            list.add(exc);
            m977f();
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        public void cancel() {
            this.f2396j = true;
            Iterator<InterfaceC1590d<Data>> it = this.f2390c.iterator();
            while (it.hasNext()) {
                it.next().cancel();
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: d */
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super Data> aVar) {
            this.f2393g = enumC1556f;
            this.f2394h = aVar;
            this.f2395i = this.f2391e.acquire();
            this.f2390c.get(this.f2392f).mo837d(enumC1556f, this);
            if (this.f2396j) {
                cancel();
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
        /* renamed from: e */
        public void mo840e(@Nullable Data data) {
            if (data != null) {
                this.f2394h.mo840e(data);
            } else {
                m977f();
            }
        }

        /* renamed from: f */
        public final void m977f() {
            if (this.f2396j) {
                return;
            }
            if (this.f2392f < this.f2390c.size() - 1) {
                this.f2392f++;
                mo837d(this.f2393g, this.f2394h);
            } else {
                Objects.requireNonNull(this.f2395i, "Argument must not be null");
                this.f2394h.mo839c(new C1650r("Fetch failed", new ArrayList(this.f2395i)));
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return this.f2390c.get(0).getDataSource();
        }
    }

    public C1675q(@NonNull List<InterfaceC1672n<Model, Data>> list, @NonNull Pools.Pool<List<Throwable>> pool) {
        this.f2388a = list;
        this.f2389b = pool;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Model model) {
        Iterator<InterfaceC1672n<Model, Data>> it = this.f2388a.iterator();
        while (it.hasNext()) {
            if (it.next().mo960a(model)) {
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<Data> mo961b(@NonNull Model model, int i2, int i3, @NonNull C1582n c1582n) {
        InterfaceC1672n.a<Data> mo961b;
        int size = this.f2388a.size();
        ArrayList arrayList = new ArrayList(size);
        InterfaceC1579k interfaceC1579k = null;
        for (int i4 = 0; i4 < size; i4++) {
            InterfaceC1672n<Model, Data> interfaceC1672n = this.f2388a.get(i4);
            if (interfaceC1672n.mo960a(model) && (mo961b = interfaceC1672n.mo961b(model, i2, i3, c1582n)) != null) {
                interfaceC1579k = mo961b.f2381a;
                arrayList.add(mo961b.f2383c);
            }
        }
        if (arrayList.isEmpty() || interfaceC1579k == null) {
            return null;
        }
        return new InterfaceC1672n.a<>(interfaceC1579k, new a(arrayList, this.f2389b));
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("MultiModelLoader{modelLoaders=");
        m586H.append(Arrays.toString(this.f2388a.toArray()));
        m586H.append('}');
        return m586H.toString();
    }
}
