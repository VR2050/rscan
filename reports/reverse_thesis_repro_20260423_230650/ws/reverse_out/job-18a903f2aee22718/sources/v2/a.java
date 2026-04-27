package v2;

import t2.j;
import x2.g;

/* JADX INFO: loaded from: classes.dex */
public abstract class a implements b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Object f10238a;

    public a(Object obj) {
        this.f10238a = obj;
    }

    @Override // v2.b
    public Object a(Object obj, g gVar) {
        j.f(gVar, "property");
        return this.f10238a;
    }

    @Override // v2.b
    public void b(Object obj, g gVar, Object obj2) {
        j.f(gVar, "property");
        Object obj3 = this.f10238a;
        if (d(gVar, obj3, obj2)) {
            this.f10238a = obj2;
            c(gVar, obj3, obj2);
        }
    }

    protected abstract void c(g gVar, Object obj, Object obj2);

    protected boolean d(g gVar, Object obj, Object obj2) {
        j.f(gVar, "property");
        return true;
    }

    public String toString() {
        return "ObservableProperty(value=" + this.f10238a + ')';
    }
}
