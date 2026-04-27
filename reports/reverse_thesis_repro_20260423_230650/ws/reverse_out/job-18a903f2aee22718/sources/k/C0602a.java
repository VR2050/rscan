package k;

import java.util.HashMap;
import java.util.Map;
import k.b;

/* JADX INFO: renamed from: k.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0602a extends b {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final HashMap f9396f = new HashMap();

    @Override // k.b
    protected b.c c(Object obj) {
        return (b.c) this.f9396f.get(obj);
    }

    public boolean contains(Object obj) {
        return this.f9396f.containsKey(obj);
    }

    @Override // k.b
    public Object i(Object obj, Object obj2) {
        b.c cVarC = c(obj);
        if (cVarC != null) {
            return cVarC.f9402b;
        }
        this.f9396f.put(obj, h(obj, obj2));
        return null;
    }

    @Override // k.b
    public Object j(Object obj) {
        Object objJ = super.j(obj);
        this.f9396f.remove(obj);
        return objJ;
    }

    public Map.Entry k(Object obj) {
        if (contains(obj)) {
            return ((b.c) this.f9396f.get(obj)).f9404d;
        }
        return null;
    }
}
