package p005b.p143g.p144a.p147m.p150t.p151c0;

import android.util.Log;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.m.t.c0.i */
/* loaded from: classes.dex */
public final class C1619i implements InterfaceC1612b {

    /* renamed from: a */
    public final C1617g<a, Object> f2065a = new C1617g<>();

    /* renamed from: b */
    public final b f2066b = new b();

    /* renamed from: c */
    public final Map<Class<?>, NavigableMap<Integer, Integer>> f2067c = new HashMap();

    /* renamed from: d */
    public final Map<Class<?>, InterfaceC1611a<?>> f2068d = new HashMap();

    /* renamed from: e */
    public final int f2069e;

    /* renamed from: f */
    public int f2070f;

    /* renamed from: b.g.a.m.t.c0.i$a */
    public static final class a implements InterfaceC1622l {

        /* renamed from: a */
        public final b f2071a;

        /* renamed from: b */
        public int f2072b;

        /* renamed from: c */
        public Class<?> f2073c;

        public a(b bVar) {
            this.f2071a = bVar;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1622l
        /* renamed from: a */
        public void mo881a() {
            this.f2071a.m866c(this);
        }

        public boolean equals(Object obj) {
            if (!(obj instanceof a)) {
                return false;
            }
            a aVar = (a) obj;
            return this.f2072b == aVar.f2072b && this.f2073c == aVar.f2073c;
        }

        public int hashCode() {
            int i2 = this.f2072b * 31;
            Class<?> cls = this.f2073c;
            return i2 + (cls != null ? cls.hashCode() : 0);
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("Key{size=");
            m586H.append(this.f2072b);
            m586H.append("array=");
            m586H.append(this.f2073c);
            m586H.append('}');
            return m586H.toString();
        }
    }

    /* renamed from: b.g.a.m.t.c0.i$b */
    public static final class b extends AbstractC1613c<a> {
        @Override // p005b.p143g.p144a.p147m.p150t.p151c0.AbstractC1613c
        /* renamed from: a */
        public a mo864a() {
            return new a(this);
        }

        /* renamed from: d */
        public a m882d(int i2, Class<?> cls) {
            a m865b = m865b();
            m865b.f2072b = i2;
            m865b.f2073c = cls;
            return m865b;
        }
    }

    public C1619i(int i2) {
        this.f2069e = i2;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b
    /* renamed from: a */
    public synchronized void mo860a(int i2) {
        if (i2 >= 40) {
            synchronized (this) {
                m877f(0);
            }
        } else if (i2 >= 20 || i2 == 15) {
            m877f(this.f2069e / 2);
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b
    /* renamed from: b */
    public synchronized void mo861b() {
        m877f(0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b
    /* renamed from: c */
    public synchronized <T> T mo862c(int i2, Class<T> cls) {
        a m865b;
        m865b = this.f2066b.m865b();
        m865b.f2072b = i2;
        m865b.f2073c = cls;
        return (T) m879h(m865b, cls);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:12:0x0023 A[Catch: all -> 0x004d, TryCatch #0 {, blocks: (B:3:0x0001, B:5:0x0013, B:7:0x0017, B:12:0x0023, B:16:0x002f, B:17:0x0047, B:22:0x003a), top: B:2:0x0001 }] */
    /* JADX WARN: Removed duplicated region for block: B:16:0x002f A[Catch: all -> 0x004d, TryCatch #0 {, blocks: (B:3:0x0001, B:5:0x0013, B:7:0x0017, B:12:0x0023, B:16:0x002f, B:17:0x0047, B:22:0x003a), top: B:2:0x0001 }] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x003a A[Catch: all -> 0x004d, TryCatch #0 {, blocks: (B:3:0x0001, B:5:0x0013, B:7:0x0017, B:12:0x0023, B:16:0x002f, B:17:0x0047, B:22:0x003a), top: B:2:0x0001 }] */
    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized <T> T mo863d(int r6, java.lang.Class<T> r7) {
        /*
            r5 = this;
            monitor-enter(r5)
            java.util.NavigableMap r0 = r5.m880i(r7)     // Catch: java.lang.Throwable -> L4d
            java.lang.Integer r1 = java.lang.Integer.valueOf(r6)     // Catch: java.lang.Throwable -> L4d
            java.lang.Object r0 = r0.ceilingKey(r1)     // Catch: java.lang.Throwable -> L4d
            java.lang.Integer r0 = (java.lang.Integer) r0     // Catch: java.lang.Throwable -> L4d
            r1 = 1
            r2 = 0
            if (r0 == 0) goto L2c
            int r3 = r5.f2070f     // Catch: java.lang.Throwable -> L4d
            if (r3 == 0) goto L20
            int r4 = r5.f2069e     // Catch: java.lang.Throwable -> L4d
            int r4 = r4 / r3
            r3 = 2
            if (r4 < r3) goto L1e
            goto L20
        L1e:
            r3 = 0
            goto L21
        L20:
            r3 = 1
        L21:
            if (r3 != 0) goto L2d
            int r3 = r0.intValue()     // Catch: java.lang.Throwable -> L4d
            int r4 = r6 * 8
            if (r3 > r4) goto L2c
            goto L2d
        L2c:
            r1 = 0
        L2d:
            if (r1 == 0) goto L3a
            b.g.a.m.t.c0.i$b r6 = r5.f2066b     // Catch: java.lang.Throwable -> L4d
            int r0 = r0.intValue()     // Catch: java.lang.Throwable -> L4d
            b.g.a.m.t.c0.i$a r6 = r6.m882d(r0, r7)     // Catch: java.lang.Throwable -> L4d
            goto L47
        L3a:
            b.g.a.m.t.c0.i$b r0 = r5.f2066b     // Catch: java.lang.Throwable -> L4d
            b.g.a.m.t.c0.l r0 = r0.m865b()     // Catch: java.lang.Throwable -> L4d
            b.g.a.m.t.c0.i$a r0 = (p005b.p143g.p144a.p147m.p150t.p151c0.C1619i.a) r0     // Catch: java.lang.Throwable -> L4d
            r0.f2072b = r6     // Catch: java.lang.Throwable -> L4d
            r0.f2073c = r7     // Catch: java.lang.Throwable -> L4d
            r6 = r0
        L47:
            java.lang.Object r6 = r5.m879h(r6, r7)     // Catch: java.lang.Throwable -> L4d
            monitor-exit(r5)
            return r6
        L4d:
            r6 = move-exception
            monitor-exit(r5)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p150t.p151c0.C1619i.mo863d(int, java.lang.Class):java.lang.Object");
    }

    /* renamed from: e */
    public final void m876e(int i2, Class<?> cls) {
        NavigableMap<Integer, Integer> m880i = m880i(cls);
        Integer num = (Integer) m880i.get(Integer.valueOf(i2));
        if (num != null) {
            if (num.intValue() == 1) {
                m880i.remove(Integer.valueOf(i2));
                return;
            } else {
                m880i.put(Integer.valueOf(i2), Integer.valueOf(num.intValue() - 1));
                return;
            }
        }
        throw new NullPointerException("Tried to decrement empty size, size: " + i2 + ", this: " + this);
    }

    /* renamed from: f */
    public final void m877f(int i2) {
        while (this.f2070f > i2) {
            Object m874c = this.f2065a.m874c();
            Objects.requireNonNull(m874c, "Argument must not be null");
            InterfaceC1611a m878g = m878g(m874c.getClass());
            this.f2070f -= m878g.mo857a() * m878g.mo858b(m874c);
            m876e(m878g.mo858b(m874c), m874c.getClass());
            if (Log.isLoggable(m878g.mo859c(), 2)) {
                m878g.mo859c();
                m878g.mo858b(m874c);
            }
        }
    }

    /* renamed from: g */
    public final <T> InterfaceC1611a<T> m878g(Class<T> cls) {
        InterfaceC1611a<T> interfaceC1611a = (InterfaceC1611a) this.f2068d.get(cls);
        if (interfaceC1611a == null) {
            if (cls.equals(int[].class)) {
                interfaceC1611a = new C1618h();
            } else {
                if (!cls.equals(byte[].class)) {
                    StringBuilder m586H = C1499a.m586H("No array pool found for: ");
                    m586H.append(cls.getSimpleName());
                    throw new IllegalArgumentException(m586H.toString());
                }
                interfaceC1611a = new C1616f();
            }
            this.f2068d.put(cls, interfaceC1611a);
        }
        return interfaceC1611a;
    }

    /* renamed from: h */
    public final <T> T m879h(a aVar, Class<T> cls) {
        InterfaceC1611a<T> m878g = m878g(cls);
        T t = (T) this.f2065a.m872a(aVar);
        if (t != null) {
            this.f2070f -= m878g.mo857a() * m878g.mo858b(t);
            m876e(m878g.mo858b(t), cls);
        }
        if (t != null) {
            return t;
        }
        if (Log.isLoggable(m878g.mo859c(), 2)) {
            m878g.mo859c();
        }
        return m878g.newArray(aVar.f2072b);
    }

    /* renamed from: i */
    public final NavigableMap<Integer, Integer> m880i(Class<?> cls) {
        NavigableMap<Integer, Integer> navigableMap = this.f2067c.get(cls);
        if (navigableMap != null) {
            return navigableMap;
        }
        TreeMap treeMap = new TreeMap();
        this.f2067c.put(cls, treeMap);
        return treeMap;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b
    public synchronized <T> void put(T t) {
        Class<?> cls = t.getClass();
        InterfaceC1611a<T> m878g = m878g(cls);
        int mo858b = m878g.mo858b(t);
        int mo857a = m878g.mo857a() * mo858b;
        int i2 = 1;
        if (mo857a <= this.f2069e / 2) {
            a m882d = this.f2066b.m882d(mo858b, cls);
            this.f2065a.m873b(m882d, t);
            NavigableMap<Integer, Integer> m880i = m880i(cls);
            Integer num = (Integer) m880i.get(Integer.valueOf(m882d.f2072b));
            Integer valueOf = Integer.valueOf(m882d.f2072b);
            if (num != null) {
                i2 = 1 + num.intValue();
            }
            m880i.put(valueOf, Integer.valueOf(i2));
            this.f2070f += mo857a;
            m877f(this.f2069e);
        }
    }
}
