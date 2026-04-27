package b0;

import X.k;
import java.util.IdentityHashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class h {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final Map f5397d = new IdentityHashMap();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Object f5398a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f5399b = 1;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final g f5400c;

    public static class a extends RuntimeException {
        public a() {
            super("Null shared reference");
        }
    }

    public h(Object obj, g gVar, boolean z3) {
        this.f5398a = k.g(obj);
        this.f5400c = gVar;
        if (z3) {
            a(obj);
        }
    }

    private static void a(Object obj) {
        Map map = f5397d;
        synchronized (map) {
            try {
                Integer num = (Integer) map.get(obj);
                if (num == null) {
                    map.put(obj, 1);
                } else {
                    map.put(obj, Integer.valueOf(num.intValue() + 1));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private synchronized int c() {
        int i3;
        e();
        k.b(Boolean.valueOf(this.f5399b > 0));
        i3 = this.f5399b - 1;
        this.f5399b = i3;
        return i3;
    }

    private void e() {
        if (!h(this)) {
            throw new a();
        }
    }

    public static boolean h(h hVar) {
        return hVar != null && hVar.g();
    }

    private static void i(Object obj) {
        Map map = f5397d;
        synchronized (map) {
            try {
                Integer num = (Integer) map.get(obj);
                if (num == null) {
                    Y.a.N("SharedReference", "No entry in sLiveObjects for value of type %s", obj.getClass());
                } else if (num.intValue() == 1) {
                    map.remove(obj);
                } else {
                    map.put(obj, Integer.valueOf(num.intValue() - 1));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public synchronized void b() {
        e();
        this.f5399b++;
    }

    public void d() {
        Object obj;
        if (c() == 0) {
            synchronized (this) {
                obj = this.f5398a;
                this.f5398a = null;
            }
            if (obj != null) {
                g gVar = this.f5400c;
                if (gVar != null) {
                    gVar.a(obj);
                }
                i(obj);
            }
        }
    }

    public synchronized Object f() {
        return this.f5398a;
    }

    public synchronized boolean g() {
        return this.f5399b > 0;
    }
}
