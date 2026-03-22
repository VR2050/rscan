package p005b.p199l.p258c;

import java.io.EOFException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;
import p005b.p199l.p258c.p260c0.C2449g;
import p005b.p199l.p258c.p260c0.C2457o;
import p005b.p199l.p258c.p260c0.C2463u;
import p005b.p199l.p258c.p260c0.p261a0.C2421a;
import p005b.p199l.p258c.p260c0.p261a0.C2422b;
import p005b.p199l.p258c.p260c0.p261a0.C2423c;
import p005b.p199l.p258c.p260c0.p261a0.C2424d;
import p005b.p199l.p258c.p260c0.p261a0.C2427g;
import p005b.p199l.p258c.p260c0.p261a0.C2428h;
import p005b.p199l.p258c.p260c0.p261a0.C2430j;
import p005b.p199l.p258c.p260c0.p261a0.C2431k;
import p005b.p199l.p258c.p260c0.p261a0.C2432l;
import p005b.p199l.p258c.p260c0.p261a0.C2435o;
import p005b.p199l.p258c.p260c0.p261a0.C2436p;
import p005b.p199l.p258c.p260c0.p261a0.C2437q;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.C2475d;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.j */
/* loaded from: classes2.dex */
public final class C2480j {

    /* renamed from: a */
    public static final C2470a<?> f6679a = C2470a.get(Object.class);

    /* renamed from: b */
    public final ThreadLocal<Map<C2470a<?>, a<?>>> f6680b;

    /* renamed from: c */
    public final Map<C2470a<?>, AbstractC2496z<?>> f6681c;

    /* renamed from: d */
    public final C2449g f6682d;

    /* renamed from: e */
    public final C2424d f6683e;

    /* renamed from: f */
    public final List<InterfaceC2415a0> f6684f;

    /* renamed from: g */
    public final Map<Type, InterfaceC2481k<?>> f6685g;

    /* renamed from: h */
    public final boolean f6686h;

    /* renamed from: i */
    public final boolean f6687i;

    /* renamed from: j */
    public final boolean f6688j;

    /* renamed from: k */
    public final boolean f6689k;

    /* renamed from: l */
    public final boolean f6690l;

    /* renamed from: m */
    public final List<InterfaceC2415a0> f6691m;

    /* renamed from: n */
    public final List<InterfaceC2415a0> f6692n;

    /* renamed from: b.l.c.j$a */
    public static class a<T> extends AbstractC2496z<T> {

        /* renamed from: a */
        public AbstractC2496z<T> f6693a;

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: b */
        public T mo2766b(C2472a c2472a) {
            AbstractC2496z<T> abstractC2496z = this.f6693a;
            if (abstractC2496z != null) {
                return abstractC2496z.mo2766b(c2472a);
            }
            throw new IllegalStateException();
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: c */
        public void mo2767c(C2474c c2474c, T t) {
            AbstractC2496z<T> abstractC2496z = this.f6693a;
            if (abstractC2496z == null) {
                throw new IllegalStateException();
            }
            abstractC2496z.mo2767c(c2474c, t);
        }
    }

    public C2480j() {
        this(C2457o.f6598c, EnumC2419c.f6445c, Collections.emptyMap(), false, false, false, true, false, false, false, EnumC2494x.f6699c, null, 2, 2, Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
    }

    /* renamed from: a */
    public static void m2847a(double d2) {
        if (Double.isNaN(d2) || Double.isInfinite(d2)) {
            throw new IllegalArgumentException(d2 + " is not a valid double value as per JSON specification. To override this behavior, use GsonBuilder.serializeSpecialFloatingPointValues() method.");
        }
    }

    /* renamed from: b */
    public <T> T m2848b(String str, Class<T> cls) {
        Object m2849c = m2849c(str, cls);
        Class<T> cls2 = (Class) C2463u.f6632a.get(cls);
        if (cls2 != null) {
            cls = cls2;
        }
        return cls.cast(m2849c);
    }

    /* JADX WARN: Finally extract failed */
    /* renamed from: c */
    public <T> T m2849c(String str, Type type) {
        T t = null;
        if (str == null) {
            return null;
        }
        C2472a c2472a = new C2472a(new StringReader(str));
        boolean z = this.f6690l;
        c2472a.f6641f = z;
        boolean z2 = true;
        c2472a.f6641f = true;
        try {
            try {
                try {
                    try {
                        c2472a.mo2777Z();
                        z2 = false;
                        t = m2850d(C2470a.get(type)).mo2766b(c2472a);
                    } catch (IOException e2) {
                        throw new C2493w(e2);
                    }
                } catch (IllegalStateException e3) {
                    throw new C2493w(e3);
                }
            } catch (EOFException e4) {
                if (!z2) {
                    throw new C2493w(e4);
                }
            } catch (AssertionError e5) {
                throw new AssertionError("AssertionError (GSON 2.8.5): " + e5.getMessage(), e5);
            }
            c2472a.f6641f = z;
            if (t != null) {
                try {
                    if (c2472a.mo2777Z() != EnumC2473b.END_DOCUMENT) {
                        throw new C2486p("JSON document was not fully consumed.");
                    }
                } catch (C2475d e6) {
                    throw new C2493w(e6);
                } catch (IOException e7) {
                    throw new C2486p(e7);
                }
            }
            return t;
        } catch (Throwable th) {
            c2472a.f6641f = z;
            throw th;
        }
    }

    /* renamed from: d */
    public <T> AbstractC2496z<T> m2850d(C2470a<T> c2470a) {
        AbstractC2496z<T> abstractC2496z = (AbstractC2496z) this.f6681c.get(c2470a == null ? f6679a : c2470a);
        if (abstractC2496z != null) {
            return abstractC2496z;
        }
        Map<C2470a<?>, a<?>> map = this.f6680b.get();
        boolean z = false;
        if (map == null) {
            map = new HashMap<>();
            this.f6680b.set(map);
            z = true;
        }
        a<?> aVar = map.get(c2470a);
        if (aVar != null) {
            return aVar;
        }
        try {
            a<?> aVar2 = new a<>();
            map.put(c2470a, aVar2);
            Iterator<InterfaceC2415a0> it = this.f6684f.iterator();
            while (it.hasNext()) {
                AbstractC2496z<T> mo2753a = it.next().mo2753a(this, c2470a);
                if (mo2753a != null) {
                    if (aVar2.f6693a != null) {
                        throw new AssertionError();
                    }
                    aVar2.f6693a = mo2753a;
                    this.f6681c.put(c2470a, mo2753a);
                    return mo2753a;
                }
            }
            throw new IllegalArgumentException("GSON (2.8.5) cannot handle " + c2470a);
        } finally {
            map.remove(c2470a);
            if (z) {
                this.f6680b.remove();
            }
        }
    }

    /* renamed from: e */
    public <T> AbstractC2496z<T> m2851e(InterfaceC2415a0 interfaceC2415a0, C2470a<T> c2470a) {
        if (!this.f6684f.contains(interfaceC2415a0)) {
            interfaceC2415a0 = this.f6683e;
        }
        boolean z = false;
        for (InterfaceC2415a0 interfaceC2415a02 : this.f6684f) {
            if (z) {
                AbstractC2496z<T> mo2753a = interfaceC2415a02.mo2753a(this, c2470a);
                if (mo2753a != null) {
                    return mo2753a;
                }
            } else if (interfaceC2415a02 == interfaceC2415a0) {
                z = true;
            }
        }
        throw new IllegalArgumentException("GSON cannot serialize " + c2470a);
    }

    /* renamed from: f */
    public C2474c m2852f(Writer writer) {
        if (this.f6687i) {
            writer.write(")]}'\n");
        }
        C2474c c2474c = new C2474c(writer);
        if (this.f6689k) {
            c2474c.f6671i = "  ";
            c2474c.f6672j = ": ";
        }
        c2474c.f6676n = this.f6686h;
        return c2474c;
    }

    /* renamed from: g */
    public String m2853g(Object obj) {
        if (obj != null) {
            return m2854h(obj, obj.getClass());
        }
        AbstractC2485o abstractC2485o = C2487q.f6695a;
        StringWriter stringWriter = new StringWriter();
        try {
            m2855i(abstractC2485o, m2852f(stringWriter));
            return stringWriter.toString();
        } catch (IOException e2) {
            throw new C2486p(e2);
        }
    }

    /* renamed from: h */
    public String m2854h(Object obj, Type type) {
        StringWriter stringWriter = new StringWriter();
        try {
            m2856j(obj, type, m2852f(stringWriter));
            return stringWriter.toString();
        } catch (IOException e2) {
            throw new C2486p(e2);
        }
    }

    /* renamed from: i */
    public void m2855i(AbstractC2485o abstractC2485o, C2474c c2474c) {
        boolean z = c2474c.f6673k;
        c2474c.f6673k = true;
        boolean z2 = c2474c.f6674l;
        c2474c.f6674l = this.f6688j;
        boolean z3 = c2474c.f6676n;
        c2474c.f6676n = this.f6686h;
        try {
            try {
                C2435o.f6538X.mo2767c(c2474c, abstractC2485o);
            } catch (IOException e2) {
                throw new C2486p(e2);
            } catch (AssertionError e3) {
                throw new AssertionError("AssertionError (GSON 2.8.5): " + e3.getMessage(), e3);
            }
        } finally {
            c2474c.f6673k = z;
            c2474c.f6674l = z2;
            c2474c.f6676n = z3;
        }
    }

    /* renamed from: j */
    public void m2856j(Object obj, Type type, C2474c c2474c) {
        AbstractC2496z m2850d = m2850d(C2470a.get(type));
        boolean z = c2474c.f6673k;
        c2474c.f6673k = true;
        boolean z2 = c2474c.f6674l;
        c2474c.f6674l = this.f6688j;
        boolean z3 = c2474c.f6676n;
        c2474c.f6676n = this.f6686h;
        try {
            try {
                try {
                    m2850d.mo2767c(c2474c, obj);
                } catch (IOException e2) {
                    throw new C2486p(e2);
                }
            } catch (AssertionError e3) {
                throw new AssertionError("AssertionError (GSON 2.8.5): " + e3.getMessage(), e3);
            }
        } finally {
            c2474c.f6673k = z;
            c2474c.f6674l = z2;
            c2474c.f6676n = z3;
        }
    }

    public String toString() {
        return "{serializeNulls:" + this.f6686h + ",factories:" + this.f6684f + ",instanceCreators:" + this.f6682d + "}";
    }

    public C2480j(C2457o c2457o, InterfaceC2469d interfaceC2469d, Map<Type, InterfaceC2481k<?>> map, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, EnumC2494x enumC2494x, String str, int i2, int i3, List<InterfaceC2415a0> list, List<InterfaceC2415a0> list2, List<InterfaceC2415a0> list3) {
        AbstractC2496z c2477g;
        AbstractC2496z c2471e;
        AbstractC2496z c2476f;
        this.f6680b = new ThreadLocal<>();
        this.f6681c = new ConcurrentHashMap();
        this.f6685g = map;
        this.f6682d = new C2449g(map);
        this.f6686h = z;
        this.f6687i = z3;
        this.f6688j = z4;
        this.f6689k = z5;
        this.f6690l = z6;
        this.f6691m = list;
        this.f6692n = list2;
        ArrayList arrayList = new ArrayList();
        arrayList.add(C2435o.f6539Y);
        arrayList.add(C2428h.f6484a);
        arrayList.add(c2457o);
        arrayList.addAll(list3);
        arrayList.add(C2435o.f6518D);
        arrayList.add(C2435o.f6553m);
        arrayList.add(C2435o.f6547g);
        arrayList.add(C2435o.f6549i);
        arrayList.add(C2435o.f6551k);
        if (enumC2494x == EnumC2494x.f6699c) {
            c2477g = C2435o.f6560t;
        } else {
            c2477g = new C2477g();
        }
        arrayList.add(new C2437q(Long.TYPE, Long.class, c2477g));
        Class cls = Double.TYPE;
        if (z7) {
            c2471e = C2435o.f6562v;
        } else {
            c2471e = new C2471e(this);
        }
        arrayList.add(new C2437q(cls, Double.class, c2471e));
        Class cls2 = Float.TYPE;
        if (z7) {
            c2476f = C2435o.f6561u;
        } else {
            c2476f = new C2476f(this);
        }
        arrayList.add(new C2437q(cls2, Float.class, c2476f));
        arrayList.add(C2435o.f6564x);
        arrayList.add(C2435o.f6555o);
        arrayList.add(C2435o.f6557q);
        arrayList.add(new C2436p(AtomicLong.class, new C2495y(new C2478h(c2477g))));
        arrayList.add(new C2436p(AtomicLongArray.class, new C2495y(new C2479i(c2477g))));
        arrayList.add(C2435o.f6559s);
        arrayList.add(C2435o.f6566z);
        arrayList.add(C2435o.f6520F);
        arrayList.add(C2435o.f6522H);
        arrayList.add(new C2436p(BigDecimal.class, C2435o.f6516B));
        arrayList.add(new C2436p(BigInteger.class, C2435o.f6517C));
        arrayList.add(C2435o.f6524J);
        arrayList.add(C2435o.f6526L);
        arrayList.add(C2435o.f6530P);
        arrayList.add(C2435o.f6532R);
        arrayList.add(C2435o.f6537W);
        arrayList.add(C2435o.f6528N);
        arrayList.add(C2435o.f6544d);
        arrayList.add(C2423c.f6465a);
        arrayList.add(C2435o.f6535U);
        arrayList.add(C2432l.f6504a);
        arrayList.add(C2431k.f6502a);
        arrayList.add(C2435o.f6533S);
        arrayList.add(C2421a.f6459a);
        arrayList.add(C2435o.f6542b);
        arrayList.add(new C2422b(this.f6682d));
        arrayList.add(new C2427g(this.f6682d, z2));
        C2424d c2424d = new C2424d(this.f6682d);
        this.f6683e = c2424d;
        arrayList.add(c2424d);
        arrayList.add(C2435o.f6540Z);
        arrayList.add(new C2430j(this.f6682d, interfaceC2469d, c2457o, c2424d));
        this.f6684f = Collections.unmodifiableList(arrayList);
    }
}
