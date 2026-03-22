package p005b.p113c0.p114a.p130l;

import androidx.annotation.NonNull;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/* renamed from: b.c0.a.l.e */
/* loaded from: classes2.dex */
public class C1493e<V> implements Map<String, V>, Serializable, Cloneable {

    /* renamed from: c */
    public final LinkedHashMap<String, V> f1502c;

    /* renamed from: e */
    public final HashMap<String, String> f1503e;

    /* renamed from: f */
    public final Locale f1504f;

    /* renamed from: b.c0.a.l.e$a */
    public class a extends LinkedHashMap<String, V> {
        public a(int i2) {
            super(i2);
        }

        @Override // java.util.HashMap, java.util.AbstractMap, java.util.Map
        public boolean containsKey(Object obj) {
            return C1493e.this.containsKey(obj);
        }

        @Override // java.util.LinkedHashMap
        public boolean removeEldestEntry(Map.Entry<String, V> entry) {
            Objects.requireNonNull(C1493e.this);
            return false;
        }
    }

    public C1493e(int i2, Locale locale) {
        this.f1502c = new a(i2);
        this.f1503e = new HashMap<>(i2);
        this.f1504f = locale == null ? Locale.getDefault() : locale;
    }

    /* renamed from: a */
    public String m564a(String str) {
        return str.toLowerCase(this.f1504f);
    }

    @Override // java.util.Map
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public V put(String str, V v) {
        String put = this.f1503e.put(str.toLowerCase(this.f1504f), str);
        if (put != null && !put.equals(str)) {
            this.f1502c.remove(put);
        }
        return this.f1502c.put(str, v);
    }

    @Override // java.util.Map
    public void clear() {
        this.f1503e.clear();
        this.f1502c.clear();
    }

    public Object clone() {
        return new C1493e(this);
    }

    @Override // java.util.Map
    public boolean containsKey(Object obj) {
        return (obj instanceof String) && this.f1503e.containsKey(m564a((String) obj));
    }

    @Override // java.util.Map
    public boolean containsValue(Object obj) {
        return this.f1502c.containsValue(obj);
    }

    @Override // java.util.Map
    @NonNull
    public Set<Map.Entry<String, V>> entrySet() {
        return this.f1502c.entrySet();
    }

    @Override // java.util.Map
    public boolean equals(Object obj) {
        return this.f1502c.equals(obj);
    }

    @Override // java.util.Map
    public V get(Object obj) {
        String str;
        if (!(obj instanceof String) || (str = this.f1503e.get(m564a((String) obj))) == null) {
            return null;
        }
        return this.f1502c.get(str);
    }

    @Override // java.util.Map
    public V getOrDefault(Object obj, V v) {
        String str;
        return (!(obj instanceof String) || (str = this.f1503e.get(m564a((String) obj))) == null) ? v : this.f1502c.get(str);
    }

    @Override // java.util.Map
    public int hashCode() {
        return this.f1502c.hashCode();
    }

    @Override // java.util.Map
    public boolean isEmpty() {
        return this.f1502c.isEmpty();
    }

    @Override // java.util.Map
    @NonNull
    public Set<String> keySet() {
        return this.f1502c.keySet();
    }

    @Override // java.util.Map
    public void putAll(@NonNull Map<? extends String, ? extends V> map) {
        if (map.isEmpty()) {
            return;
        }
        for (Map.Entry<? extends String, ? extends V> entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    @Override // java.util.Map
    public V remove(Object obj) {
        String remove;
        if (!(obj instanceof String) || (remove = this.f1503e.remove(m564a((String) obj))) == null) {
            return null;
        }
        return this.f1502c.remove(remove);
    }

    @Override // java.util.Map
    public int size() {
        return this.f1502c.size();
    }

    public String toString() {
        return this.f1502c.toString();
    }

    @Override // java.util.Map
    @NonNull
    public Collection<V> values() {
        return this.f1502c.values();
    }

    public C1493e(C1493e<V> c1493e) {
        this.f1502c = (LinkedHashMap) c1493e.f1502c.clone();
        this.f1503e = (HashMap) c1493e.f1503e.clone();
        this.f1504f = c1493e.f1504f;
    }
}
