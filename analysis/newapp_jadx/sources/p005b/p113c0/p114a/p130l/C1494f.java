package p005b.p113c0.p114a.p130l;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* renamed from: b.c0.a.l.f */
/* loaded from: classes2.dex */
public class C1494f<K, V> implements InterfaceC1497i<K, V>, Cloneable {

    /* renamed from: c */
    public final Map<K, List<V>> f1506c;

    public C1494f() {
        this.f1506c = new LinkedHashMap();
    }

    /* renamed from: a */
    public void m566a(K k2, V v) {
        List<V> list = this.f1506c.get(k2);
        if (list == null) {
            list = new LinkedList<>();
            this.f1506c.put(k2, list);
        }
        list.add(v);
    }

    /* renamed from: c */
    public V m567c(K k2) {
        List<V> list = this.f1506c.get(k2);
        if (list != null) {
            return list.get(0);
        }
        return null;
    }

    @Override // java.util.Map
    public void clear() {
        this.f1506c.clear();
    }

    public Object clone() {
        return new C1494f(this);
    }

    @Override // java.util.Map
    public boolean containsKey(Object obj) {
        return this.f1506c.containsKey(obj);
    }

    @Override // java.util.Map
    public boolean containsValue(Object obj) {
        return this.f1506c.containsValue(obj);
    }

    @Override // java.util.Map
    public Set<Map.Entry<K, List<V>>> entrySet() {
        return this.f1506c.entrySet();
    }

    @Override // java.util.Map
    public boolean equals(Object obj) {
        return this.f1506c.equals(obj);
    }

    @Override // java.util.Map
    public Object get(Object obj) {
        return this.f1506c.get(obj);
    }

    @Override // java.util.Map
    public int hashCode() {
        return this.f1506c.hashCode();
    }

    @Override // java.util.Map
    public boolean isEmpty() {
        return this.f1506c.isEmpty();
    }

    @Override // java.util.Map
    public Set<K> keySet() {
        return this.f1506c.keySet();
    }

    @Override // java.util.Map
    public Object put(Object obj, Object obj2) {
        return this.f1506c.put(obj, (List) obj2);
    }

    @Override // java.util.Map
    public void putAll(Map<? extends K, ? extends List<V>> map) {
        this.f1506c.putAll(map);
    }

    @Override // java.util.Map
    public Object remove(Object obj) {
        return this.f1506c.remove(obj);
    }

    @Override // java.util.Map
    public int size() {
        return this.f1506c.size();
    }

    public String toString() {
        return this.f1506c.toString();
    }

    @Override // java.util.Map
    public Collection<List<V>> values() {
        return this.f1506c.values();
    }

    public C1494f(Map<K, List<V>> map) {
        this.f1506c = new LinkedHashMap(map);
    }
}
