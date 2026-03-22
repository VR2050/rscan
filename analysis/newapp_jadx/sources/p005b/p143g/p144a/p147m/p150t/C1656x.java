package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1557g;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1639g;
import p005b.p143g.p144a.p147m.p154u.C1674p;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p165p.C1771d;
import p005b.p143g.p144a.p170s.C1806h;

/* renamed from: b.g.a.m.t.x */
/* loaded from: classes.dex */
public class C1656x implements InterfaceC1639g, InterfaceC1590d.a<Object> {

    /* renamed from: c */
    public final InterfaceC1639g.a f2318c;

    /* renamed from: e */
    public final C1640h<?> f2319e;

    /* renamed from: f */
    public int f2320f;

    /* renamed from: g */
    public int f2321g = -1;

    /* renamed from: h */
    public InterfaceC1579k f2322h;

    /* renamed from: i */
    public List<InterfaceC1672n<File, ?>> f2323i;

    /* renamed from: j */
    public int f2324j;

    /* renamed from: k */
    public volatile InterfaceC1672n.a<?> f2325k;

    /* renamed from: l */
    public File f2326l;

    /* renamed from: m */
    public C1657y f2327m;

    public C1656x(C1640h<?> c1640h, InterfaceC1639g.a aVar) {
        this.f2319e = c1640h;
        this.f2318c = aVar;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g
    /* renamed from: b */
    public boolean mo854b() {
        List<Class<?>> list;
        List<Class<?>> m981d;
        List<InterfaceC1579k> m906a = this.f2319e.m906a();
        if (m906a.isEmpty()) {
            return false;
        }
        C1640h<?> c1640h = this.f2319e;
        C1557g c1557g = c1640h.f2151c.f1836c;
        Class<?> cls = c1640h.f2152d.getClass();
        Class<?> cls2 = c1640h.f2155g;
        Class<?> cls3 = c1640h.f2159k;
        C1771d c1771d = c1557g.f1857h;
        C1806h andSet = c1771d.f2643a.getAndSet(null);
        if (andSet == null) {
            andSet = new C1806h(cls, cls2, cls3);
        } else {
            andSet.f2764a = cls;
            andSet.f2765b = cls2;
            andSet.f2766c = cls3;
        }
        synchronized (c1771d.f2644b) {
            list = c1771d.f2644b.get(andSet);
        }
        c1771d.f2643a.set(andSet);
        List<Class<?>> list2 = list;
        if (list == null) {
            ArrayList arrayList = new ArrayList();
            C1674p c1674p = c1557g.f1850a;
            synchronized (c1674p) {
                m981d = c1674p.f2384a.m981d(cls);
            }
            Iterator it = ((ArrayList) m981d).iterator();
            while (it.hasNext()) {
                Iterator it2 = ((ArrayList) c1557g.f1852c.m1067b((Class) it.next(), cls2)).iterator();
                while (it2.hasNext()) {
                    Class cls4 = (Class) it2.next();
                    if (!((ArrayList) c1557g.f1855f.m1038a(cls4, cls3)).isEmpty() && !arrayList.contains(cls4)) {
                        arrayList.add(cls4);
                    }
                }
            }
            C1771d c1771d2 = c1557g.f1857h;
            List<Class<?>> unmodifiableList = Collections.unmodifiableList(arrayList);
            synchronized (c1771d2.f2644b) {
                c1771d2.f2644b.put(new C1806h(cls, cls2, cls3), unmodifiableList);
            }
            list2 = arrayList;
        }
        if (list2.isEmpty()) {
            if (File.class.equals(this.f2319e.f2159k)) {
                return false;
            }
            StringBuilder m586H = C1499a.m586H("Failed to find any load path from ");
            m586H.append(this.f2319e.f2152d.getClass());
            m586H.append(" to ");
            m586H.append(this.f2319e.f2159k);
            throw new IllegalStateException(m586H.toString());
        }
        while (true) {
            List<InterfaceC1672n<File, ?>> list3 = this.f2323i;
            if (list3 != null) {
                if (this.f2324j < list3.size()) {
                    this.f2325k = null;
                    boolean z = false;
                    while (!z) {
                        if (!(this.f2324j < this.f2323i.size())) {
                            break;
                        }
                        List<InterfaceC1672n<File, ?>> list4 = this.f2323i;
                        int i2 = this.f2324j;
                        this.f2324j = i2 + 1;
                        InterfaceC1672n<File, ?> interfaceC1672n = list4.get(i2);
                        File file = this.f2326l;
                        C1640h<?> c1640h2 = this.f2319e;
                        this.f2325k = interfaceC1672n.mo961b(file, c1640h2.f2153e, c1640h2.f2154f, c1640h2.f2157i);
                        if (this.f2325k != null && this.f2319e.m912g(this.f2325k.f2383c.mo832a())) {
                            this.f2325k.f2383c.mo837d(this.f2319e.f2163o, this);
                            z = true;
                        }
                    }
                    return z;
                }
            }
            int i3 = this.f2321g + 1;
            this.f2321g = i3;
            if (i3 >= list2.size()) {
                int i4 = this.f2320f + 1;
                this.f2320f = i4;
                if (i4 >= m906a.size()) {
                    return false;
                }
                this.f2321g = 0;
            }
            InterfaceC1579k interfaceC1579k = m906a.get(this.f2320f);
            Class<?> cls5 = list2.get(this.f2321g);
            InterfaceC1586r<Z> m911f = this.f2319e.m911f(cls5);
            C1640h<?> c1640h3 = this.f2319e;
            this.f2327m = new C1657y(c1640h3.f2151c.f1835b, interfaceC1579k, c1640h3.f2162n, c1640h3.f2153e, c1640h3.f2154f, m911f, cls5, c1640h3.f2157i);
            File mo895b = c1640h3.m907b().mo895b(this.f2327m);
            this.f2326l = mo895b;
            if (mo895b != null) {
                this.f2322h = interfaceC1579k;
                this.f2323i = this.f2319e.f2151c.f1836c.m748f(mo895b);
                this.f2324j = 0;
            }
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
    /* renamed from: c */
    public void mo839c(@NonNull Exception exc) {
        this.f2318c.mo853a(this.f2327m, exc, this.f2325k.f2383c, EnumC1569a.RESOURCE_DISK_CACHE);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g
    public void cancel() {
        InterfaceC1672n.a<?> aVar = this.f2325k;
        if (aVar != null) {
            aVar.f2383c.cancel();
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
    /* renamed from: e */
    public void mo840e(Object obj) {
        this.f2318c.mo856d(this.f2322h, obj, this.f2325k.f2383c, EnumC1569a.RESOURCE_DISK_CACHE, this.f2327m);
    }
}
