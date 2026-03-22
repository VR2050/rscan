package p476m.p496b.p497a;

import android.os.Looper;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p496b.p497a.InterfaceC4914h;

/* renamed from: m.b.a.c */
/* loaded from: classes3.dex */
public class C4909c {

    /* renamed from: a */
    public static volatile C4909c f12508a;

    /* renamed from: b */
    public static final C4910d f12509b = new C4910d();

    /* renamed from: c */
    public static final Map<Class<?>, List<Class<?>>> f12510c = new HashMap();

    /* renamed from: d */
    public final Map<Class<?>, CopyOnWriteArrayList<C4923q>> f12511d;

    /* renamed from: e */
    public final Map<Object, List<Class<?>>> f12512e;

    /* renamed from: f */
    public final Map<Class<?>, Object> f12513f;

    /* renamed from: g */
    public final ThreadLocal<b> f12514g;

    /* renamed from: h */
    public final InterfaceC4914h f12515h;

    /* renamed from: i */
    public final InterfaceC4918l f12516i;

    /* renamed from: j */
    public final RunnableC4908b f12517j;

    /* renamed from: k */
    public final RunnableC4907a f12518k;

    /* renamed from: l */
    public final C4922p f12519l;

    /* renamed from: m */
    public final ExecutorService f12520m;

    /* renamed from: n */
    public final boolean f12521n;

    /* renamed from: o */
    public final boolean f12522o;

    /* renamed from: p */
    public final boolean f12523p;

    /* renamed from: q */
    public final boolean f12524q;

    /* renamed from: r */
    public final boolean f12525r;

    /* renamed from: s */
    public final InterfaceC4913g f12526s;

    /* renamed from: m.b.a.c$a */
    public class a extends ThreadLocal<b> {
        public a(C4909c c4909c) {
        }

        @Override // java.lang.ThreadLocal
        public b initialValue() {
            return new b();
        }
    }

    /* renamed from: m.b.a.c$b */
    public static final class b {

        /* renamed from: a */
        public final List<Object> f12527a = new ArrayList();

        /* renamed from: b */
        public boolean f12528b;

        /* renamed from: c */
        public boolean f12529c;

        /* renamed from: d */
        public Object f12530d;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0044 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0058  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C4909c() {
        /*
            r5 = this;
            m.b.a.d r0 = p476m.p496b.p497a.C4909c.f12509b
            r5.<init>()
            m.b.a.c$a r1 = new m.b.a.c$a
            r1.<init>(r5)
            r5.f12514g = r1
            java.util.Objects.requireNonNull(r0)
            boolean r1 = p476m.p496b.p497a.p498r.C4924a.f12571a
            r2 = 0
            if (r1 == 0) goto L24
            android.os.Looper r1 = android.os.Looper.getMainLooper()     // Catch: java.lang.RuntimeException -> L19
            goto L1a
        L19:
            r1 = r2
        L1a:
            if (r1 == 0) goto L24
            m.b.a.r.a r1 = new m.b.a.r.a
            java.lang.String r3 = "EventBus"
            r1.<init>(r3)
            goto L29
        L24:
            m.b.a.g$b r1 = new m.b.a.g$b
            r1.<init>()
        L29:
            r5.f12526s = r1
            java.util.HashMap r1 = new java.util.HashMap
            r1.<init>()
            r5.f12511d = r1
            java.util.HashMap r1 = new java.util.HashMap
            r1.<init>()
            r5.f12512e = r1
            java.util.concurrent.ConcurrentHashMap r1 = new java.util.concurrent.ConcurrentHashMap
            r1.<init>()
            r5.f12513f = r1
            boolean r1 = p476m.p496b.p497a.p498r.C4924a.f12571a
            if (r1 == 0) goto L53
            android.os.Looper r1 = android.os.Looper.getMainLooper()     // Catch: java.lang.RuntimeException -> L49
            goto L4a
        L49:
            r1 = r2
        L4a:
            if (r1 != 0) goto L4d
            goto L53
        L4d:
            m.b.a.h$a r3 = new m.b.a.h$a
            r3.<init>(r1)
            goto L54
        L53:
            r3 = r2
        L54:
            r5.f12515h = r3
            if (r3 == 0) goto L62
            m.b.a.f r1 = new m.b.a.f
            android.os.Looper r3 = r3.f12542a
            r4 = 10
            r1.<init>(r5, r3, r4)
            goto L63
        L62:
            r1 = r2
        L63:
            r5.f12516i = r1
            m.b.a.b r1 = new m.b.a.b
            r1.<init>(r5)
            r5.f12517j = r1
            m.b.a.a r1 = new m.b.a.a
            r1.<init>(r5)
            r5.f12518k = r1
            r1 = 0
            m.b.a.p r3 = new m.b.a.p
            r3.<init>(r2, r1, r1)
            r5.f12519l = r3
            r1 = 1
            r5.f12521n = r1
            r5.f12522o = r1
            r5.f12523p = r1
            r5.f12524q = r1
            r5.f12525r = r1
            java.util.concurrent.ExecutorService r0 = r0.f12532b
            r5.f12520m = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p496b.p497a.C4909c.<init>():void");
    }

    /* renamed from: a */
    public static void m5568a(List<Class<?>> list, Class<?>[] clsArr) {
        for (Class<?> cls : clsArr) {
            if (!list.contains(cls)) {
                list.add(cls);
                m5568a(list, cls.getInterfaces());
            }
        }
    }

    /* renamed from: b */
    public static C4909c m5569b() {
        C4909c c4909c = f12508a;
        if (c4909c == null) {
            synchronized (C4909c.class) {
                c4909c = f12508a;
                if (c4909c == null) {
                    c4909c = new C4909c();
                    f12508a = c4909c;
                }
            }
        }
        return c4909c;
    }

    /* renamed from: c */
    public void m5570c(C4916j c4916j) {
        Object obj = c4916j.f12545b;
        C4923q c4923q = c4916j.f12546c;
        c4916j.f12545b = null;
        c4916j.f12546c = null;
        c4916j.f12547d = null;
        List<C4916j> list = C4916j.f12544a;
        synchronized (list) {
            if (list.size() < 10000) {
                list.add(c4916j);
            }
        }
        if (c4923q.f12570c) {
            m5571d(c4923q, obj);
        }
    }

    /* renamed from: d */
    public void m5571d(C4923q c4923q, Object obj) {
        try {
            c4923q.f12569b.f12553a.invoke(c4923q.f12568a, obj);
        } catch (IllegalAccessException e2) {
            throw new IllegalStateException("Unexpected exception", e2);
        } catch (InvocationTargetException e3) {
            Throwable cause = e3.getCause();
            if (!(obj instanceof C4920n)) {
                if (this.f12521n) {
                    InterfaceC4913g interfaceC4913g = this.f12526s;
                    Level level = Level.SEVERE;
                    StringBuilder m586H = C1499a.m586H("Could not dispatch event: ");
                    m586H.append(obj.getClass());
                    m586H.append(" to subscribing class ");
                    m586H.append(c4923q.f12568a.getClass());
                    interfaceC4913g.mo5582b(level, m586H.toString(), cause);
                }
                if (this.f12523p) {
                    m5574g(new C4920n(this, cause, obj, c4923q.f12568a));
                    return;
                }
                return;
            }
            if (this.f12521n) {
                InterfaceC4913g interfaceC4913g2 = this.f12526s;
                Level level2 = Level.SEVERE;
                StringBuilder m586H2 = C1499a.m586H("SubscriberExceptionEvent subscriber ");
                m586H2.append(c4923q.f12568a.getClass());
                m586H2.append(" threw an exception");
                interfaceC4913g2.mo5582b(level2, m586H2.toString(), cause);
                C4920n c4920n = (C4920n) obj;
                InterfaceC4913g interfaceC4913g3 = this.f12526s;
                StringBuilder m586H3 = C1499a.m586H("Initial event ");
                m586H3.append(c4920n.f12551b);
                m586H3.append(" caused exception in ");
                m586H3.append(c4920n.f12552c);
                interfaceC4913g3.mo5582b(level2, m586H3.toString(), c4920n.f12550a);
            }
        }
    }

    /* renamed from: e */
    public final boolean m5572e() {
        InterfaceC4914h interfaceC4914h = this.f12515h;
        if (interfaceC4914h != null) {
            if (!(((InterfaceC4914h.a) interfaceC4914h).f12542a == Looper.myLooper())) {
                return false;
            }
        }
        return true;
    }

    /* renamed from: f */
    public synchronized boolean m5573f(Object obj) {
        return this.f12512e.containsKey(obj);
    }

    /* renamed from: g */
    public void m5574g(Object obj) {
        b bVar = this.f12514g.get();
        List<Object> list = bVar.f12527a;
        list.add(obj);
        if (bVar.f12528b) {
            return;
        }
        bVar.f12529c = m5572e();
        bVar.f12528b = true;
        while (true) {
            try {
                if (list.isEmpty()) {
                    return;
                } else {
                    m5575h(list.remove(0), bVar);
                }
            } finally {
                bVar.f12528b = false;
                bVar.f12529c = false;
            }
        }
    }

    /* renamed from: h */
    public final void m5575h(Object obj, b bVar) {
        boolean m5576i;
        List<Class<?>> list;
        Class<?> cls = obj.getClass();
        if (this.f12525r) {
            Map<Class<?>, List<Class<?>>> map = f12510c;
            synchronized (map) {
                List<Class<?>> list2 = map.get(cls);
                list = list2;
                if (list2 == null) {
                    ArrayList arrayList = new ArrayList();
                    for (Class<?> cls2 = cls; cls2 != null; cls2 = cls2.getSuperclass()) {
                        arrayList.add(cls2);
                        m5568a(arrayList, cls2.getInterfaces());
                    }
                    f12510c.put(cls, arrayList);
                    list = arrayList;
                }
            }
            int size = list.size();
            m5576i = false;
            for (int i2 = 0; i2 < size; i2++) {
                m5576i |= m5576i(obj, bVar, list.get(i2));
            }
        } else {
            m5576i = m5576i(obj, bVar, cls);
        }
        if (m5576i) {
            return;
        }
        if (this.f12522o) {
            this.f12526s.mo5581a(Level.FINE, "No subscribers registered for event " + cls);
        }
        if (!this.f12524q || cls == C4915i.class || cls == C4920n.class) {
            return;
        }
        m5574g(new C4915i(this, obj));
    }

    /* renamed from: i */
    public final boolean m5576i(Object obj, b bVar, Class<?> cls) {
        CopyOnWriteArrayList<C4923q> copyOnWriteArrayList;
        synchronized (this) {
            copyOnWriteArrayList = this.f12511d.get(cls);
        }
        if (copyOnWriteArrayList == null || copyOnWriteArrayList.isEmpty()) {
            return false;
        }
        Iterator<C4923q> it = copyOnWriteArrayList.iterator();
        while (it.hasNext()) {
            C4923q next = it.next();
            bVar.f12530d = obj;
            m5577j(next, obj, bVar.f12529c);
        }
        return true;
    }

    /* renamed from: j */
    public final void m5577j(C4923q c4923q, Object obj, boolean z) {
        int ordinal = c4923q.f12569b.f12554b.ordinal();
        if (ordinal == 0) {
            m5571d(c4923q, obj);
            return;
        }
        if (ordinal == 1) {
            if (z) {
                m5571d(c4923q, obj);
                return;
            } else {
                this.f12516i.mo5567a(c4923q, obj);
                return;
            }
        }
        if (ordinal == 2) {
            InterfaceC4918l interfaceC4918l = this.f12516i;
            if (interfaceC4918l != null) {
                interfaceC4918l.mo5567a(c4923q, obj);
                return;
            } else {
                m5571d(c4923q, obj);
                return;
            }
        }
        if (ordinal == 3) {
            if (z) {
                this.f12517j.mo5567a(c4923q, obj);
                return;
            } else {
                m5571d(c4923q, obj);
                return;
            }
        }
        if (ordinal == 4) {
            this.f12518k.mo5567a(c4923q, obj);
        } else {
            StringBuilder m586H = C1499a.m586H("Unknown thread mode: ");
            m586H.append(c4923q.f12569b.f12554b);
            throw new IllegalStateException(m586H.toString());
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x003a, code lost:
    
        if (r2.f12565e == r5.m5597c()) goto L16;
     */
    /* renamed from: k */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m5578k(java.lang.Object r12) {
        /*
            r11 = this;
            java.lang.Class r0 = r12.getClass()
            m.b.a.p r1 = r11.f12519l
            java.util.Objects.requireNonNull(r1)
            java.util.Map<java.lang.Class<?>, java.util.List<m.b.a.o>> r2 = p476m.p496b.p497a.C4922p.f12559a
            java.lang.Object r2 = r2.get(r0)
            java.util.List r2 = (java.util.List) r2
            if (r2 == 0) goto L14
            goto L77
        L14:
            m.b.a.p$a r2 = r1.m5590c()
            r2.f12565e = r0
            r3 = 0
            r2.f12566f = r3
            r4 = 0
            r2.f12567g = r4
        L20:
            java.lang.Class<?> r5 = r2.f12565e
            if (r5 == 0) goto L65
            m.b.a.s.a r5 = r2.f12567g
            if (r5 == 0) goto L3d
            m.b.a.s.a r5 = r5.m5596b()
            if (r5 == 0) goto L3d
            m.b.a.s.a r5 = r2.f12567g
            m.b.a.s.a r5 = r5.m5596b()
            java.lang.Class<?> r6 = r2.f12565e
            java.lang.Class r7 = r5.m5597c()
            if (r6 != r7) goto L3d
            goto L3e
        L3d:
            r5 = r4
        L3e:
            r2.f12567g = r5
            if (r5 == 0) goto L5e
            m.b.a.o[] r5 = r5.m5595a()
            int r6 = r5.length
            r7 = 0
        L48:
            if (r7 >= r6) goto L61
            r8 = r5[r7]
            java.lang.reflect.Method r9 = r8.f12553a
            java.lang.Class<?> r10 = r8.f12555c
            boolean r9 = r2.m5591a(r9, r10)
            if (r9 == 0) goto L5b
            java.util.List<m.b.a.o> r9 = r2.f12561a
            r9.add(r8)
        L5b:
            int r7 = r7 + 1
            goto L48
        L5e:
            r1.m5588a(r2)
        L61:
            r2.m5593c()
            goto L20
        L65:
            java.util.List r2 = r1.m5589b(r2)
            r1 = r2
            java.util.ArrayList r1 = (java.util.ArrayList) r1
            boolean r1 = r1.isEmpty()
            if (r1 != 0) goto L91
            java.util.Map<java.lang.Class<?>, java.util.List<m.b.a.o>> r1 = p476m.p496b.p497a.C4922p.f12559a
            r1.put(r0, r2)
        L77:
            monitor-enter(r11)
            java.util.Iterator r0 = r2.iterator()     // Catch: java.lang.Throwable -> L8e
        L7c:
            boolean r1 = r0.hasNext()     // Catch: java.lang.Throwable -> L8e
            if (r1 == 0) goto L8c
            java.lang.Object r1 = r0.next()     // Catch: java.lang.Throwable -> L8e
            m.b.a.o r1 = (p476m.p496b.p497a.C4921o) r1     // Catch: java.lang.Throwable -> L8e
            r11.m5579l(r12, r1)     // Catch: java.lang.Throwable -> L8e
            goto L7c
        L8c:
            monitor-exit(r11)     // Catch: java.lang.Throwable -> L8e
            return
        L8e:
            r12 = move-exception
            monitor-exit(r11)     // Catch: java.lang.Throwable -> L8e
            throw r12
        L91:
            m.b.a.e r12 = new m.b.a.e
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "Subscriber "
            r1.append(r2)
            r1.append(r0)
            java.lang.String r0 = " and its super classes have no public methods with the @Subscribe annotation"
            r1.append(r0)
            java.lang.String r0 = r1.toString()
            r12.<init>(r0)
            throw r12
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p496b.p497a.C4909c.m5578k(java.lang.Object):void");
    }

    /* renamed from: l */
    public final void m5579l(Object obj, C4921o c4921o) {
        Object value;
        Class<?> cls = c4921o.f12555c;
        C4923q c4923q = new C4923q(obj, c4921o);
        CopyOnWriteArrayList<C4923q> copyOnWriteArrayList = this.f12511d.get(cls);
        if (copyOnWriteArrayList == null) {
            copyOnWriteArrayList = new CopyOnWriteArrayList<>();
            this.f12511d.put(cls, copyOnWriteArrayList);
        } else if (copyOnWriteArrayList.contains(c4923q)) {
            StringBuilder m586H = C1499a.m586H("Subscriber ");
            m586H.append(obj.getClass());
            m586H.append(" already registered to event ");
            m586H.append(cls);
            throw new C4911e(m586H.toString());
        }
        int size = copyOnWriteArrayList.size();
        for (int i2 = 0; i2 <= size; i2++) {
            if (i2 == size || c4921o.f12556d > copyOnWriteArrayList.get(i2).f12569b.f12556d) {
                copyOnWriteArrayList.add(i2, c4923q);
                break;
            }
        }
        List<Class<?>> list = this.f12512e.get(obj);
        if (list == null) {
            list = new ArrayList<>();
            this.f12512e.put(obj, list);
        }
        list.add(cls);
        if (c4921o.f12557e) {
            if (!this.f12525r) {
                Object obj2 = this.f12513f.get(cls);
                if (obj2 != null) {
                    m5577j(c4923q, obj2, m5572e());
                    return;
                }
                return;
            }
            for (Map.Entry<Class<?>, Object> entry : this.f12513f.entrySet()) {
                if (cls.isAssignableFrom(entry.getKey()) && (value = entry.getValue()) != null) {
                    m5577j(c4923q, value, m5572e());
                }
            }
        }
    }

    /* renamed from: m */
    public synchronized void m5580m(Object obj) {
        List<Class<?>> list = this.f12512e.get(obj);
        if (list != null) {
            Iterator<Class<?>> it = list.iterator();
            while (it.hasNext()) {
                CopyOnWriteArrayList<C4923q> copyOnWriteArrayList = this.f12511d.get(it.next());
                if (copyOnWriteArrayList != null) {
                    int size = copyOnWriteArrayList.size();
                    int i2 = 0;
                    while (i2 < size) {
                        C4923q c4923q = copyOnWriteArrayList.get(i2);
                        if (c4923q.f12568a == obj) {
                            c4923q.f12570c = false;
                            copyOnWriteArrayList.remove(i2);
                            i2--;
                            size--;
                        }
                        i2++;
                    }
                }
            }
            this.f12512e.remove(obj);
        } else {
            this.f12526s.mo5581a(Level.WARNING, "Subscriber to unregister was not registered before: " + obj.getClass());
        }
    }

    public String toString() {
        StringBuilder m588J = C1499a.m588J("EventBus[indexCount=", 0, ", eventInheritance=");
        m588J.append(this.f12525r);
        m588J.append("]");
        return m588J.toString();
    }
}
