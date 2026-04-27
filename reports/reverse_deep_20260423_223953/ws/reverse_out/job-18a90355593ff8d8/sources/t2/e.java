package t2;

import h2.C0563i;
import i2.AbstractC0586n;
import i2.D;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import r2.AbstractC0677a;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class e implements x2.b, d {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f10199b = new a(null);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final Map f10200c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final HashMap f10201d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final HashMap f10202e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final HashMap f10203f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final Map f10204g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Class f10205a;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    static {
        List listI = AbstractC0586n.i(InterfaceC0688a.class, s2.l.class, s2.p.class, s2.q.class, s2.r.class, s2.s.class, s2.t.class, s2.u.class, s2.v.class, s2.w.class, s2.b.class, s2.c.class, s2.d.class, s2.e.class, s2.f.class, s2.g.class, s2.h.class, s2.i.class, s2.j.class, s2.k.class, s2.m.class, s2.n.class, s2.o.class);
        ArrayList arrayList = new ArrayList(AbstractC0586n.o(listI, 10));
        int i3 = 0;
        for (Object obj : listI) {
            int i4 = i3 + 1;
            if (i3 < 0) {
                AbstractC0586n.n();
            }
            arrayList.add(h2.n.a((Class) obj, Integer.valueOf(i3)));
            i3 = i4;
        }
        f10200c = D.m(arrayList);
        HashMap map = new HashMap();
        map.put("boolean", "kotlin.Boolean");
        map.put("char", "kotlin.Char");
        map.put("byte", "kotlin.Byte");
        map.put("short", "kotlin.Short");
        map.put("int", "kotlin.Int");
        map.put("float", "kotlin.Float");
        map.put("long", "kotlin.Long");
        map.put("double", "kotlin.Double");
        f10201d = map;
        HashMap map2 = new HashMap();
        map2.put("java.lang.Boolean", "kotlin.Boolean");
        map2.put("java.lang.Character", "kotlin.Char");
        map2.put("java.lang.Byte", "kotlin.Byte");
        map2.put("java.lang.Short", "kotlin.Short");
        map2.put("java.lang.Integer", "kotlin.Int");
        map2.put("java.lang.Float", "kotlin.Float");
        map2.put("java.lang.Long", "kotlin.Long");
        map2.put("java.lang.Double", "kotlin.Double");
        f10202e = map2;
        HashMap map3 = new HashMap();
        map3.put("java.lang.Object", "kotlin.Any");
        map3.put("java.lang.String", "kotlin.String");
        map3.put("java.lang.CharSequence", "kotlin.CharSequence");
        map3.put("java.lang.Throwable", "kotlin.Throwable");
        map3.put("java.lang.Cloneable", "kotlin.Cloneable");
        map3.put("java.lang.Number", "kotlin.Number");
        map3.put("java.lang.Comparable", "kotlin.Comparable");
        map3.put("java.lang.Enum", "kotlin.Enum");
        map3.put("java.lang.annotation.Annotation", "kotlin.Annotation");
        map3.put("java.lang.Iterable", "kotlin.collections.Iterable");
        map3.put("java.util.Iterator", "kotlin.collections.Iterator");
        map3.put("java.util.Collection", "kotlin.collections.Collection");
        map3.put("java.util.List", "kotlin.collections.List");
        map3.put("java.util.Set", "kotlin.collections.Set");
        map3.put("java.util.ListIterator", "kotlin.collections.ListIterator");
        map3.put("java.util.Map", "kotlin.collections.Map");
        map3.put("java.util.Map$Entry", "kotlin.collections.Map.Entry");
        map3.put("kotlin.jvm.internal.StringCompanionObject", "kotlin.String.Companion");
        map3.put("kotlin.jvm.internal.EnumCompanionObject", "kotlin.Enum.Companion");
        map3.putAll(map);
        map3.putAll(map2);
        Collection<String> collectionValues = map.values();
        j.e(collectionValues, "<get-values>(...)");
        for (String str : collectionValues) {
            StringBuilder sb = new StringBuilder();
            sb.append("kotlin.jvm.internal.");
            j.c(str);
            sb.append(z2.g.m0(str, '.', null, 2, null));
            sb.append("CompanionObject");
            C0563i c0563iA = h2.n.a(sb.toString(), str + ".Companion");
            map3.put(c0563iA.c(), c0563iA.d());
        }
        for (Map.Entry entry : f10200c.entrySet()) {
            map3.put(((Class) entry.getKey()).getName(), "kotlin.Function" + ((Number) entry.getValue()).intValue());
        }
        f10203f = map3;
        LinkedHashMap linkedHashMap = new LinkedHashMap(D.c(map3.size()));
        for (Map.Entry entry2 : map3.entrySet()) {
            linkedHashMap.put(entry2.getKey(), z2.g.m0((String) entry2.getValue(), '.', null, 2, null));
        }
        f10204g = linkedHashMap;
    }

    public e(Class cls) {
        j.f(cls, "jClass");
        this.f10205a = cls;
    }

    @Override // t2.d
    public Class a() {
        return this.f10205a;
    }

    public boolean equals(Object obj) {
        return (obj instanceof e) && j.b(AbstractC0677a.b(this), AbstractC0677a.b((x2.b) obj));
    }

    public int hashCode() {
        return AbstractC0677a.b(this).hashCode();
    }

    public String toString() {
        return a().toString() + " (Kotlin reflection is not available)";
    }
}
