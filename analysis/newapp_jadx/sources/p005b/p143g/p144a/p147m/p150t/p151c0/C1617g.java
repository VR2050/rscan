package p005b.p143g.p144a.p147m.p150t.p151c0;

import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1622l;

/* renamed from: b.g.a.m.t.c0.g */
/* loaded from: classes.dex */
public class C1617g<K extends InterfaceC1622l, V> {

    /* renamed from: a */
    public final a<K, V> f2059a = new a<>(null);

    /* renamed from: b */
    public final Map<K, a<K, V>> f2060b = new HashMap();

    /* renamed from: b.g.a.m.t.c0.g$a */
    public static class a<K, V> {

        /* renamed from: a */
        public final K f2061a;

        /* renamed from: b */
        public List<V> f2062b;

        /* renamed from: c */
        public a<K, V> f2063c;

        /* renamed from: d */
        public a<K, V> f2064d;

        public a() {
            this(null);
        }

        @Nullable
        /* renamed from: a */
        public V m875a() {
            List<V> list = this.f2062b;
            int size = list != null ? list.size() : 0;
            if (size > 0) {
                return this.f2062b.remove(size - 1);
            }
            return null;
        }

        public a(K k2) {
            this.f2064d = this;
            this.f2063c = this;
            this.f2061a = k2;
        }
    }

    @Nullable
    /* renamed from: a */
    public V m872a(K k2) {
        a<K, V> aVar = this.f2060b.get(k2);
        if (aVar == null) {
            aVar = new a<>(k2);
            this.f2060b.put(k2, aVar);
        } else {
            k2.mo881a();
        }
        a<K, V> aVar2 = aVar.f2064d;
        aVar2.f2063c = aVar.f2063c;
        aVar.f2063c.f2064d = aVar2;
        a<K, V> aVar3 = this.f2059a;
        aVar.f2064d = aVar3;
        a<K, V> aVar4 = aVar3.f2063c;
        aVar.f2063c = aVar4;
        aVar4.f2064d = aVar;
        aVar.f2064d.f2063c = aVar;
        return aVar.m875a();
    }

    /* renamed from: b */
    public void m873b(K k2, V v) {
        a<K, V> aVar = this.f2060b.get(k2);
        if (aVar == null) {
            aVar = new a<>(k2);
            a<K, V> aVar2 = aVar.f2064d;
            aVar2.f2063c = aVar.f2063c;
            aVar.f2063c.f2064d = aVar2;
            a<K, V> aVar3 = this.f2059a;
            aVar.f2064d = aVar3.f2064d;
            aVar.f2063c = aVar3;
            aVar3.f2064d = aVar;
            aVar.f2064d.f2063c = aVar;
            this.f2060b.put(k2, aVar);
        } else {
            k2.mo881a();
        }
        if (aVar.f2062b == null) {
            aVar.f2062b = new ArrayList();
        }
        aVar.f2062b.add(v);
    }

    @Nullable
    /* renamed from: c */
    public V m874c() {
        for (a aVar = this.f2059a.f2064d; !aVar.equals(this.f2059a); aVar = aVar.f2064d) {
            V v = (V) aVar.m875a();
            if (v != null) {
                return v;
            }
            a<K, V> aVar2 = aVar.f2064d;
            aVar2.f2063c = aVar.f2063c;
            aVar.f2063c.f2064d = aVar2;
            this.f2060b.remove(aVar.f2061a);
            ((InterfaceC1622l) aVar.f2061a).mo881a();
        }
        return null;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("GroupedLinkedMap( ");
        boolean z = false;
        for (a aVar = this.f2059a.f2063c; !aVar.equals(this.f2059a); aVar = aVar.f2063c) {
            z = true;
            sb.append('{');
            sb.append(aVar.f2061a);
            sb.append(':');
            List<V> list = aVar.f2062b;
            sb.append(list != null ? list.size() : 0);
            sb.append("}, ");
        }
        if (z) {
            sb.delete(sb.length() - 2, sb.length());
        }
        sb.append(" )");
        return sb.toString();
    }
}
