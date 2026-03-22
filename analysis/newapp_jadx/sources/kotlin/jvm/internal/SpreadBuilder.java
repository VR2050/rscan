package kotlin.jvm.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class SpreadBuilder {
    private final ArrayList<Object> list;

    public SpreadBuilder(int i2) {
        this.list = new ArrayList<>(i2);
    }

    public void add(Object obj) {
        this.list.add(obj);
    }

    public void addSpread(Object obj) {
        if (obj == null) {
            return;
        }
        if (obj instanceof Object[]) {
            Object[] objArr = (Object[]) obj;
            if (objArr.length > 0) {
                ArrayList<Object> arrayList = this.list;
                arrayList.ensureCapacity(arrayList.size() + objArr.length);
                Collections.addAll(this.list, objArr);
                return;
            }
            return;
        }
        if (obj instanceof Collection) {
            this.list.addAll((Collection) obj);
            return;
        }
        if (obj instanceof Iterable) {
            Iterator it = ((Iterable) obj).iterator();
            while (it.hasNext()) {
                this.list.add(it.next());
            }
            return;
        }
        if (!(obj instanceof Iterator)) {
            StringBuilder m586H = C1499a.m586H("Don't know how to spread ");
            m586H.append(obj.getClass());
            throw new UnsupportedOperationException(m586H.toString());
        }
        Iterator it2 = (Iterator) obj;
        while (it2.hasNext()) {
            this.list.add(it2.next());
        }
    }

    public int size() {
        return this.list.size();
    }

    public Object[] toArray(Object[] objArr) {
        return this.list.toArray(objArr);
    }
}
