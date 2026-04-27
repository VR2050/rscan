package l;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/* JADX INFO: renamed from: l.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0606a extends C0612g implements Map {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    AbstractC0611f f9424i;

    /* JADX INFO: renamed from: l.a$a, reason: collision with other inner class name */
    class C0137a extends AbstractC0611f {
        C0137a() {
        }

        @Override // l.AbstractC0611f
        protected void a() {
            C0606a.this.clear();
        }

        @Override // l.AbstractC0611f
        protected Object b(int i3, int i4) {
            return C0606a.this.f9473c[(i3 << 1) + i4];
        }

        @Override // l.AbstractC0611f
        protected Map c() {
            return C0606a.this;
        }

        @Override // l.AbstractC0611f
        protected int d() {
            return C0606a.this.f9474d;
        }

        @Override // l.AbstractC0611f
        protected int e(Object obj) {
            return C0606a.this.f(obj);
        }

        @Override // l.AbstractC0611f
        protected int f(Object obj) {
            return C0606a.this.h(obj);
        }

        @Override // l.AbstractC0611f
        protected void g(Object obj, Object obj2) {
            C0606a.this.put(obj, obj2);
        }

        @Override // l.AbstractC0611f
        protected void h(int i3) {
            C0606a.this.j(i3);
        }

        @Override // l.AbstractC0611f
        protected Object i(int i3, Object obj) {
            return C0606a.this.k(i3, obj);
        }
    }

    private AbstractC0611f m() {
        if (this.f9424i == null) {
            this.f9424i = new C0137a();
        }
        return this.f9424i;
    }

    @Override // java.util.Map
    public Set entrySet() {
        return m().l();
    }

    @Override // java.util.Map
    public Set keySet() {
        return m().m();
    }

    public boolean n(Collection collection) {
        return AbstractC0611f.p(this, collection);
    }

    @Override // java.util.Map
    public void putAll(Map map) {
        c(this.f9474d + map.size());
        for (Map.Entry entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    @Override // java.util.Map
    public Collection values() {
        return m().n();
    }
}
