package p005b.p199l.p258c.p260c0.p261a0;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.AbstractC2485o;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.C2482l;
import p005b.p199l.p258c.C2486p;
import p005b.p199l.p258c.C2487q;
import p005b.p199l.p258c.C2488r;
import p005b.p199l.p258c.C2490t;
import p005b.p199l.p258c.C2493w;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p260c0.AbstractC2459q;
import p005b.p199l.p258c.p260c0.C2420a;
import p005b.p199l.p258c.p260c0.C2449g;
import p005b.p199l.p258c.p260c0.InterfaceC2462t;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.g */
/* loaded from: classes2.dex */
public final class C2427g implements InterfaceC2415a0 {

    /* renamed from: c */
    public final C2449g f6478c;

    /* renamed from: e */
    public final boolean f6479e;

    /* renamed from: b.l.c.c0.a0.g$a */
    public final class a<K, V> extends AbstractC2496z<Map<K, V>> {

        /* renamed from: a */
        public final AbstractC2496z<K> f6480a;

        /* renamed from: b */
        public final AbstractC2496z<V> f6481b;

        /* renamed from: c */
        public final InterfaceC2462t<? extends Map<K, V>> f6482c;

        public a(C2480j c2480j, Type type, AbstractC2496z<K> abstractC2496z, Type type2, AbstractC2496z<V> abstractC2496z2, InterfaceC2462t<? extends Map<K, V>> interfaceC2462t) {
            this.f6480a = new C2434n(c2480j, abstractC2496z, type);
            this.f6481b = new C2434n(c2480j, abstractC2496z2, type2);
            this.f6482c = interfaceC2462t;
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: b */
        public Object mo2766b(C2472a c2472a) {
            EnumC2473b mo2777Z = c2472a.mo2777Z();
            if (mo2777Z == EnumC2473b.NULL) {
                c2472a.mo2775V();
                return null;
            }
            Map<K, V> mo2810a = this.f6482c.mo2810a();
            if (mo2777Z == EnumC2473b.BEGIN_ARRAY) {
                c2472a.mo2778b();
                while (c2472a.mo2787t()) {
                    c2472a.mo2778b();
                    K mo2766b = this.f6480a.mo2766b(c2472a);
                    if (mo2810a.put(mo2766b, this.f6481b.mo2766b(c2472a)) != null) {
                        throw new C2493w(C1499a.m636v("duplicate key: ", mo2766b));
                    }
                    c2472a.mo2785o();
                }
                c2472a.mo2785o();
            } else {
                c2472a.mo2779d();
                while (c2472a.mo2787t()) {
                    Objects.requireNonNull((C2472a.a) AbstractC2459q.f6608a);
                    if (c2472a instanceof C2425e) {
                        C2425e c2425e = (C2425e) c2472a;
                        c2425e.m2781g0(EnumC2473b.NAME);
                        Map.Entry entry = (Map.Entry) ((Iterator) c2425e.m2782h0()).next();
                        c2425e.m2784j0(entry.getValue());
                        c2425e.m2784j0(new C2490t((String) entry.getKey()));
                    } else {
                        int i2 = c2472a.f6647l;
                        if (i2 == 0) {
                            i2 = c2472a.m2836k();
                        }
                        if (i2 == 13) {
                            c2472a.f6647l = 9;
                        } else if (i2 == 12) {
                            c2472a.f6647l = 8;
                        } else {
                            if (i2 != 14) {
                                StringBuilder m586H = C1499a.m586H("Expected a name but was ");
                                m586H.append(c2472a.mo2777Z());
                                m586H.append(c2472a.m2826C());
                                throw new IllegalStateException(m586H.toString());
                            }
                            c2472a.f6647l = 10;
                        }
                    }
                    K mo2766b2 = this.f6480a.mo2766b(c2472a);
                    if (mo2810a.put(mo2766b2, this.f6481b.mo2766b(c2472a)) != null) {
                        throw new C2493w(C1499a.m636v("duplicate key: ", mo2766b2));
                    }
                }
                c2472a.mo2786q();
            }
            return mo2810a;
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: c */
        public void mo2767c(C2474c c2474c, Object obj) {
            String str;
            Map map = (Map) obj;
            if (map == null) {
                c2474c.mo2800v();
                return;
            }
            if (!C2427g.this.f6479e) {
                c2474c.mo2796e();
                for (Map.Entry<K, V> entry : map.entrySet()) {
                    c2474c.mo2799s(String.valueOf(entry.getKey()));
                    this.f6481b.mo2767c(c2474c, entry.getValue());
                }
                c2474c.mo2798q();
                return;
            }
            ArrayList arrayList = new ArrayList(map.size());
            ArrayList arrayList2 = new ArrayList(map.size());
            int i2 = 0;
            boolean z = false;
            for (Map.Entry<K, V> entry2 : map.entrySet()) {
                AbstractC2496z<K> abstractC2496z = this.f6480a;
                K key = entry2.getKey();
                Objects.requireNonNull(abstractC2496z);
                try {
                    C2426f c2426f = new C2426f();
                    abstractC2496z.mo2767c(c2426f, key);
                    if (!c2426f.f6475q.isEmpty()) {
                        throw new IllegalStateException("Expected one JSON element but was " + c2426f.f6475q);
                    }
                    AbstractC2485o abstractC2485o = c2426f.f6477s;
                    arrayList.add(abstractC2485o);
                    arrayList2.add(entry2.getValue());
                    Objects.requireNonNull(abstractC2485o);
                    z |= (abstractC2485o instanceof C2482l) || (abstractC2485o instanceof C2488r);
                } catch (IOException e2) {
                    throw new C2486p(e2);
                }
            }
            if (z) {
                c2474c.mo2795d();
                int size = arrayList.size();
                while (i2 < size) {
                    c2474c.mo2795d();
                    C2435o.f6538X.mo2767c(c2474c, (AbstractC2485o) arrayList.get(i2));
                    this.f6481b.mo2767c(c2474c, arrayList2.get(i2));
                    c2474c.mo2797o();
                    i2++;
                }
                c2474c.mo2797o();
                return;
            }
            c2474c.mo2796e();
            int size2 = arrayList.size();
            while (i2 < size2) {
                AbstractC2485o abstractC2485o2 = (AbstractC2485o) arrayList.get(i2);
                Objects.requireNonNull(abstractC2485o2);
                if (abstractC2485o2 instanceof C2490t) {
                    C2490t m2859a = abstractC2485o2.m2859a();
                    Object obj2 = m2859a.f6698b;
                    if (obj2 instanceof Number) {
                        str = String.valueOf(m2859a.m2862c());
                    } else if (obj2 instanceof Boolean) {
                        str = Boolean.toString(m2859a.m2861b());
                    } else {
                        if (!(obj2 instanceof String)) {
                            throw new AssertionError();
                        }
                        str = m2859a.m2863d();
                    }
                } else {
                    if (!(abstractC2485o2 instanceof C2487q)) {
                        throw new AssertionError();
                    }
                    str = "null";
                }
                c2474c.mo2799s(str);
                this.f6481b.mo2767c(c2474c, arrayList2.get(i2));
                i2++;
            }
            c2474c.mo2798q();
        }
    }

    public C2427g(C2449g c2449g, boolean z) {
        this.f6478c = c2449g;
        this.f6479e = z;
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
        Type[] actualTypeArguments;
        Type type = c2470a.getType();
        if (!Map.class.isAssignableFrom(c2470a.getRawType())) {
            return null;
        }
        Class<?> m2761e = C2420a.m2761e(type);
        if (type == Properties.class) {
            actualTypeArguments = new Type[]{String.class, String.class};
        } else {
            Type m2762f = C2420a.m2762f(type, m2761e, Map.class);
            actualTypeArguments = m2762f instanceof ParameterizedType ? ((ParameterizedType) m2762f).getActualTypeArguments() : new Type[]{Object.class, Object.class};
        }
        Type type2 = actualTypeArguments[0];
        return new a(c2480j, actualTypeArguments[0], (type2 == Boolean.TYPE || type2 == Boolean.class) ? C2435o.f6546f : c2480j.m2850d(C2470a.get(type2)), actualTypeArguments[1], c2480j.m2850d(C2470a.get(actualTypeArguments[1])), this.f6478c.m2812a(c2470a));
    }
}
