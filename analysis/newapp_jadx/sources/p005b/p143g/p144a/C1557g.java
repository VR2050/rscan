package p005b.p143g.p144a;

import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import com.bumptech.glide.load.ImageHeaderParser;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.InterfaceC1572d;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.InterfaceC1585q;
import p005b.p143g.p144a.p147m.p148s.C1592f;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;
import p005b.p143g.p144a.p147m.p154u.C1674p;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1673o;
import p005b.p143g.p144a.p147m.p156v.p162h.C1745f;
import p005b.p143g.p144a.p147m.p156v.p162h.InterfaceC1744e;
import p005b.p143g.p144a.p165p.C1768a;
import p005b.p143g.p144a.p165p.C1769b;
import p005b.p143g.p144a.p165p.C1770c;
import p005b.p143g.p144a.p165p.C1771d;
import p005b.p143g.p144a.p165p.C1772e;
import p005b.p143g.p144a.p165p.C1773f;
import p005b.p143g.p144a.p170s.p171j.C1808a;
import p005b.p143g.p144a.p170s.p171j.C1809b;
import p005b.p143g.p144a.p170s.p171j.C1810c;

/* renamed from: b.g.a.g */
/* loaded from: classes.dex */
public class C1557g {

    /* renamed from: a */
    public final C1674p f1850a;

    /* renamed from: b */
    public final C1768a f1851b;

    /* renamed from: c */
    public final C1772e f1852c;

    /* renamed from: d */
    public final C1773f f1853d;

    /* renamed from: e */
    public final C1592f f1854e;

    /* renamed from: f */
    public final C1745f f1855f;

    /* renamed from: g */
    public final C1769b f1856g;

    /* renamed from: h */
    public final C1771d f1857h = new C1771d();

    /* renamed from: i */
    public final C1770c f1858i = new C1770c();

    /* renamed from: j */
    public final Pools.Pool<List<Throwable>> f1859j;

    /* renamed from: b.g.a.g$a */
    public static class a extends RuntimeException {
        public a(@NonNull String str) {
            super(str);
        }
    }

    /* renamed from: b.g.a.g$b */
    public static final class b extends a {
        public b() {
            super("Failed to find image header parser.");
        }
    }

    /* renamed from: b.g.a.g$c */
    public static class c extends a {
        /* JADX WARN: Illegal instructions before constructor call */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public c(@androidx.annotation.NonNull java.lang.Object r2) {
            /*
                r1 = this;
                java.lang.String r0 = "Failed to find any ModelLoaders registered for model class: "
                java.lang.StringBuilder r0 = p005b.p131d.p132a.p133a.C1499a.m586H(r0)
                java.lang.Class r2 = r2.getClass()
                r0.append(r2)
                java.lang.String r2 = r0.toString()
                r1.<init>(r2)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.C1557g.c.<init>(java.lang.Object):void");
        }

        public <M> c(@NonNull M m2, @NonNull List<InterfaceC1672n<M, ?>> list) {
            super("Found ModelLoaders for model class: " + list + ", but none that handle this specific model instance: " + m2);
        }

        public c(@NonNull Class<?> cls, @NonNull Class<?> cls2) {
            super("Failed to find any ModelLoaders for model: " + cls + " and data: " + cls2);
        }
    }

    /* renamed from: b.g.a.g$d */
    public static class d extends a {
        public d(@NonNull Class<?> cls) {
            super("Failed to find result encoder for resource class: " + cls + ", you may need to consider registering a new Encoder for the requested type or DiskCacheStrategy.DATA/DiskCacheStrategy.NONE if caching your transformed resource is unnecessary.");
        }
    }

    /* renamed from: b.g.a.g$e */
    public static class e extends a {
        public e(@NonNull Class<?> cls) {
            super(C1499a.m635u("Failed to find source encoder for data class: ", cls));
        }
    }

    public C1557g() {
        C1808a.c cVar = new C1808a.c(new Pools.SynchronizedPool(20), new C1809b(), new C1810c());
        this.f1859j = cVar;
        this.f1850a = new C1674p(cVar);
        this.f1851b = new C1768a();
        C1772e c1772e = new C1772e();
        this.f1852c = c1772e;
        this.f1853d = new C1773f();
        this.f1854e = new C1592f();
        this.f1855f = new C1745f();
        this.f1856g = new C1769b();
        List asList = Arrays.asList("Gif", "Bitmap", "BitmapDrawable");
        ArrayList arrayList = new ArrayList(asList.size());
        arrayList.addAll(asList);
        arrayList.add(0, "legacy_prepend_all");
        arrayList.add("legacy_append");
        synchronized (c1772e) {
            ArrayList arrayList2 = new ArrayList(c1772e.f2645a);
            c1772e.f2645a.clear();
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                c1772e.f2645a.add((String) it.next());
            }
            Iterator it2 = arrayList2.iterator();
            while (it2.hasNext()) {
                String str = (String) it2.next();
                if (!arrayList.contains(str)) {
                    c1772e.f2645a.add(str);
                }
            }
        }
    }

    @NonNull
    /* renamed from: a */
    public <Data> C1557g m743a(@NonNull Class<Data> cls, @NonNull InterfaceC1572d<Data> interfaceC1572d) {
        C1768a c1768a = this.f1851b;
        synchronized (c1768a) {
            c1768a.f2636a.add(new C1768a.a<>(cls, interfaceC1572d));
        }
        return this;
    }

    @NonNull
    /* renamed from: b */
    public <TResource> C1557g m744b(@NonNull Class<TResource> cls, @NonNull InterfaceC1585q<TResource> interfaceC1585q) {
        C1773f c1773f = this.f1853d;
        synchronized (c1773f) {
            c1773f.f2650a.add(new C1773f.a<>(cls, interfaceC1585q));
        }
        return this;
    }

    @NonNull
    /* renamed from: c */
    public <Model, Data> C1557g m745c(@NonNull Class<Model> cls, @NonNull Class<Data> cls2, @NonNull InterfaceC1673o<Model, Data> interfaceC1673o) {
        C1674p c1674p = this.f1850a;
        synchronized (c1674p) {
            C1676r c1676r = c1674p.f2384a;
            synchronized (c1676r) {
                C1676r.b<?, ?> bVar = new C1676r.b<>(cls, cls2, interfaceC1673o);
                List<C1676r.b<?, ?>> list = c1676r.f2399c;
                list.add(list.size(), bVar);
            }
            c1674p.f2385b.f2386a.clear();
        }
        return this;
    }

    @NonNull
    /* renamed from: d */
    public <Data, TResource> C1557g m746d(@NonNull String str, @NonNull Class<Data> cls, @NonNull Class<TResource> cls2, @NonNull InterfaceC1584p<Data, TResource> interfaceC1584p) {
        C1772e c1772e = this.f1852c;
        synchronized (c1772e) {
            c1772e.m1066a(str).add(new C1772e.a<>(cls, cls2, interfaceC1584p));
        }
        return this;
    }

    @NonNull
    /* renamed from: e */
    public List<ImageHeaderParser> m747e() {
        List<ImageHeaderParser> list;
        C1769b c1769b = this.f1856g;
        synchronized (c1769b) {
            list = c1769b.f2639a;
        }
        if (list.isEmpty()) {
            throw new b();
        }
        return list;
    }

    @NonNull
    /* renamed from: f */
    public <Model> List<InterfaceC1672n<Model, ?>> m748f(@NonNull Model model) {
        List<InterfaceC1672n<?, ?>> list;
        C1674p c1674p = this.f1850a;
        Objects.requireNonNull(c1674p);
        Class<?> cls = model.getClass();
        synchronized (c1674p) {
            C1674p.a.C5110a<?> c5110a = c1674p.f2385b.f2386a.get(cls);
            list = c5110a == null ? null : c5110a.f2387a;
            if (list == null) {
                list = Collections.unmodifiableList(c1674p.f2384a.m980c(cls));
                if (c1674p.f2385b.f2386a.put(cls, new C1674p.a.C5110a<>(list)) != null) {
                    throw new IllegalStateException("Already cached loaders for model: " + cls);
                }
            }
        }
        if (list.isEmpty()) {
            throw new c(model);
        }
        int size = list.size();
        List<InterfaceC1672n<Model, ?>> emptyList = Collections.emptyList();
        boolean z = true;
        for (int i2 = 0; i2 < size; i2++) {
            InterfaceC1672n<?, ?> interfaceC1672n = list.get(i2);
            if (interfaceC1672n.mo960a(model)) {
                if (z) {
                    emptyList = new ArrayList<>(size - i2);
                    z = false;
                }
                emptyList.add(interfaceC1672n);
            }
        }
        if (emptyList.isEmpty()) {
            throw new c(model, (List<InterfaceC1672n<Model, ?>>) list);
        }
        return emptyList;
    }

    @NonNull
    /* renamed from: g */
    public C1557g m749g(@NonNull InterfaceC1591e.a<?> aVar) {
        C1592f c1592f = this.f1854e;
        synchronized (c1592f) {
            c1592f.f2007b.put(aVar.mo843a(), aVar);
        }
        return this;
    }

    @NonNull
    /* renamed from: h */
    public <TResource, Transcode> C1557g m750h(@NonNull Class<TResource> cls, @NonNull Class<Transcode> cls2, @NonNull InterfaceC1744e<TResource, Transcode> interfaceC1744e) {
        C1745f c1745f = this.f1855f;
        synchronized (c1745f) {
            c1745f.f2602a.add(new C1745f.a<>(cls, cls2, interfaceC1744e));
        }
        return this;
    }
}
