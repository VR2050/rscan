package p005b.p143g.p144a.p147m.p150t;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p143g.p144a.C1555e;
import p005b.p143g.p144a.C1557g;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.C1644l;
import p005b.p143g.p144a.p147m.p150t.RunnableC1641i;
import p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1625a;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p156v.C1690b;
import p005b.p143g.p144a.p147m.p156v.p162h.C1745f;
import p005b.p143g.p144a.p147m.p156v.p162h.C1746g;
import p005b.p143g.p144a.p147m.p156v.p162h.InterfaceC1744e;
import p005b.p143g.p144a.p165p.C1770c;
import p005b.p143g.p144a.p165p.C1772e;
import p005b.p143g.p144a.p170s.C1806h;

/* renamed from: b.g.a.m.t.h */
/* loaded from: classes.dex */
public final class C1640h<Transcode> {

    /* renamed from: a */
    public final List<InterfaceC1672n.a<?>> f2149a = new ArrayList();

    /* renamed from: b */
    public final List<InterfaceC1579k> f2150b = new ArrayList();

    /* renamed from: c */
    public C1555e f2151c;

    /* renamed from: d */
    public Object f2152d;

    /* renamed from: e */
    public int f2153e;

    /* renamed from: f */
    public int f2154f;

    /* renamed from: g */
    public Class<?> f2155g;

    /* renamed from: h */
    public RunnableC1641i.d f2156h;

    /* renamed from: i */
    public C1582n f2157i;

    /* renamed from: j */
    public Map<Class<?>, InterfaceC1586r<?>> f2158j;

    /* renamed from: k */
    public Class<Transcode> f2159k;

    /* renamed from: l */
    public boolean f2160l;

    /* renamed from: m */
    public boolean f2161m;

    /* renamed from: n */
    public InterfaceC1579k f2162n;

    /* renamed from: o */
    public EnumC1556f f2163o;

    /* renamed from: p */
    public AbstractC1643k f2164p;

    /* renamed from: q */
    public boolean f2165q;

    /* renamed from: r */
    public boolean f2166r;

    /* renamed from: a */
    public List<InterfaceC1579k> m906a() {
        if (!this.f2161m) {
            this.f2161m = true;
            this.f2150b.clear();
            List<InterfaceC1672n.a<?>> m908c = m908c();
            int size = m908c.size();
            for (int i2 = 0; i2 < size; i2++) {
                InterfaceC1672n.a<?> aVar = m908c.get(i2);
                if (!this.f2150b.contains(aVar.f2381a)) {
                    this.f2150b.add(aVar.f2381a);
                }
                for (int i3 = 0; i3 < aVar.f2382b.size(); i3++) {
                    if (!this.f2150b.contains(aVar.f2382b.get(i3))) {
                        this.f2150b.add(aVar.f2382b.get(i3));
                    }
                }
            }
        }
        return this.f2150b;
    }

    /* renamed from: b */
    public InterfaceC1625a m907b() {
        return ((C1644l.c) this.f2156h).m938a();
    }

    /* renamed from: c */
    public List<InterfaceC1672n.a<?>> m908c() {
        if (!this.f2160l) {
            this.f2160l = true;
            this.f2149a.clear();
            List m748f = this.f2151c.f1836c.m748f(this.f2152d);
            int size = m748f.size();
            for (int i2 = 0; i2 < size; i2++) {
                InterfaceC1672n.a<?> mo961b = ((InterfaceC1672n) m748f.get(i2)).mo961b(this.f2152d, this.f2153e, this.f2154f, this.f2157i);
                if (mo961b != null) {
                    this.f2149a.add(mo961b);
                }
            }
        }
        return this.f2149a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: d */
    public <Data> C1653u<Data, ?, Transcode> m909d(Class<Data> cls) {
        C1653u<Data, ?, Transcode> c1653u;
        ArrayList arrayList;
        InterfaceC1744e interfaceC1744e;
        C1557g c1557g = this.f2151c.f1836c;
        Class<?> cls2 = this.f2155g;
        Class<Transcode> cls3 = this.f2159k;
        C1770c c1770c = c1557g.f1858i;
        C1806h andSet = c1770c.f2642c.getAndSet(null);
        if (andSet == null) {
            andSet = new C1806h();
        }
        andSet.f2764a = cls;
        andSet.f2765b = cls2;
        andSet.f2766c = cls3;
        synchronized (c1770c.f2641b) {
            c1653u = (C1653u) c1770c.f2641b.get(andSet);
        }
        c1770c.f2642c.set(andSet);
        Objects.requireNonNull(c1557g.f1858i);
        if (C1770c.f2640a.equals(c1653u)) {
            return null;
        }
        if (c1653u != null) {
            return c1653u;
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it = ((ArrayList) c1557g.f1852c.m1067b(cls, cls2)).iterator();
        while (it.hasNext()) {
            Class<?> cls4 = (Class) it.next();
            Iterator it2 = ((ArrayList) c1557g.f1855f.m1038a(cls4, cls3)).iterator();
            while (it2.hasNext()) {
                Class<?> cls5 = (Class) it2.next();
                C1772e c1772e = c1557g.f1852c;
                synchronized (c1772e) {
                    arrayList = new ArrayList();
                    Iterator<String> it3 = c1772e.f2645a.iterator();
                    while (it3.hasNext()) {
                        List<C1772e.a<?, ?>> list = c1772e.f2646b.get(it3.next());
                        if (list != null) {
                            for (C1772e.a<?, ?> aVar : list) {
                                if (aVar.m1068a(cls, cls4)) {
                                    arrayList.add(aVar.f2649c);
                                }
                            }
                        }
                    }
                }
                C1745f c1745f = c1557g.f1855f;
                synchronized (c1745f) {
                    if (!cls5.isAssignableFrom(cls4)) {
                        for (C1745f.a<?, ?> aVar2 : c1745f.f2602a) {
                            if (aVar2.m1039a(cls4, cls5)) {
                                interfaceC1744e = aVar2.f2605c;
                            }
                        }
                        throw new IllegalArgumentException("No transcoder registered to transcode from " + cls4 + " to " + cls5);
                    }
                    interfaceC1744e = C1746g.f2606a;
                }
                arrayList2.add(new C1642j(cls, cls4, cls5, arrayList, interfaceC1744e, c1557g.f1859j));
            }
        }
        C1653u<Data, ?, Transcode> c1653u2 = arrayList2.isEmpty() ? null : new C1653u<>(cls, cls2, cls3, arrayList2, c1557g.f1859j);
        C1770c c1770c2 = c1557g.f1858i;
        synchronized (c1770c2.f2641b) {
            c1770c2.f2641b.put(new C1806h(cls, cls2, cls3), c1653u2 != null ? c1653u2 : C1770c.f2640a);
        }
        return c1653u2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0025, code lost:
    
        r1 = (p005b.p143g.p144a.p147m.InterfaceC1572d<X>) r3.f2638b;
     */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public <X> p005b.p143g.p144a.p147m.InterfaceC1572d<X> m910e(X r6) {
        /*
            r5 = this;
            b.g.a.e r0 = r5.f2151c
            b.g.a.g r0 = r0.f1836c
            b.g.a.p.a r0 = r0.f1851b
            java.lang.Class r1 = r6.getClass()
            monitor-enter(r0)
            java.util.List<b.g.a.p.a$a<?>> r2 = r0.f2636a     // Catch: java.lang.Throwable -> L38
            java.util.Iterator r2 = r2.iterator()     // Catch: java.lang.Throwable -> L38
        L11:
            boolean r3 = r2.hasNext()     // Catch: java.lang.Throwable -> L38
            if (r3 == 0) goto L29
            java.lang.Object r3 = r2.next()     // Catch: java.lang.Throwable -> L38
            b.g.a.p.a$a r3 = (p005b.p143g.p144a.p165p.C1768a.a) r3     // Catch: java.lang.Throwable -> L38
            java.lang.Class<T> r4 = r3.f2637a     // Catch: java.lang.Throwable -> L38
            boolean r4 = r4.isAssignableFrom(r1)     // Catch: java.lang.Throwable -> L38
            if (r4 == 0) goto L11
            b.g.a.m.d<T> r1 = r3.f2638b     // Catch: java.lang.Throwable -> L38
            monitor-exit(r0)
            goto L2b
        L29:
            r1 = 0
            monitor-exit(r0)
        L2b:
            if (r1 == 0) goto L2e
            return r1
        L2e:
            b.g.a.g$e r0 = new b.g.a.g$e
            java.lang.Class r6 = r6.getClass()
            r0.<init>(r6)
            throw r0
        L38:
            r6 = move-exception
            monitor-exit(r0)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p150t.C1640h.m910e(java.lang.Object):b.g.a.m.d");
    }

    /* renamed from: f */
    public <Z> InterfaceC1586r<Z> m911f(Class<Z> cls) {
        InterfaceC1586r<Z> interfaceC1586r = (InterfaceC1586r) this.f2158j.get(cls);
        if (interfaceC1586r == null) {
            Iterator<Map.Entry<Class<?>, InterfaceC1586r<?>>> it = this.f2158j.entrySet().iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                Map.Entry<Class<?>, InterfaceC1586r<?>> next = it.next();
                if (next.getKey().isAssignableFrom(cls)) {
                    interfaceC1586r = (InterfaceC1586r) next.getValue();
                    break;
                }
            }
        }
        if (interfaceC1586r != null) {
            return interfaceC1586r;
        }
        if (!this.f2158j.isEmpty() || !this.f2165q) {
            return (C1690b) C1690b.f2459b;
        }
        throw new IllegalArgumentException("Missing transformation for " + cls + ". If you wish to ignore unknown resource types, use the optional transformation methods.");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: g */
    public boolean m912g(Class<?> cls) {
        return m909d(cls) != null;
    }
}
