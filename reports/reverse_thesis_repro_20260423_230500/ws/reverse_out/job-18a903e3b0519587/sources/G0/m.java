package G0;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final D f804a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final LinkedHashMap f805b = new LinkedHashMap();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f806c = 0;

    public m(D d3) {
        this.f804a = d3;
    }

    private int f(Object obj) {
        if (obj == null) {
            return 0;
        }
        return this.f804a.a(obj);
    }

    public synchronized Object a(Object obj) {
        return this.f805b.get(obj);
    }

    public synchronized int b() {
        return this.f805b.size();
    }

    public synchronized Object c() {
        return this.f805b.isEmpty() ? null : this.f805b.keySet().iterator().next();
    }

    public synchronized ArrayList d(X.l lVar) {
        ArrayList arrayList;
        try {
            arrayList = new ArrayList(this.f805b.entrySet().size());
            for (Map.Entry entry : this.f805b.entrySet()) {
                if (lVar == null || lVar.a(entry.getKey())) {
                    arrayList.add(entry);
                }
            }
        } catch (Throwable th) {
            throw th;
        }
        return arrayList;
    }

    public synchronized int e() {
        return this.f806c;
    }

    public synchronized Object g(Object obj, Object obj2) {
        Object objRemove;
        objRemove = this.f805b.remove(obj);
        this.f806c -= f(objRemove);
        this.f805b.put(obj, obj2);
        this.f806c += f(obj2);
        return objRemove;
    }

    public synchronized Object h(Object obj) {
        Object objRemove;
        objRemove = this.f805b.remove(obj);
        this.f806c -= f(objRemove);
        return objRemove;
    }

    public synchronized ArrayList i(X.l lVar) {
        ArrayList arrayList;
        try {
            arrayList = new ArrayList();
            Iterator it = this.f805b.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry entry = (Map.Entry) it.next();
                if (lVar == null || lVar.a(entry.getKey())) {
                    arrayList.add(entry.getValue());
                    this.f806c -= f(entry.getValue());
                    it.remove();
                }
            }
        } catch (Throwable th) {
            throw th;
        }
        return arrayList;
    }

    public synchronized void j() {
        if (this.f805b.isEmpty()) {
            this.f806c = 0;
        }
    }
}
