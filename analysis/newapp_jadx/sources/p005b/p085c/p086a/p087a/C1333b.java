package p005b.p085c.p086a.p087a;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.TreeSet;
import org.json.alipay.C5071a;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.a.a.b */
/* loaded from: classes.dex */
public final class C1333b implements InterfaceC1340i, InterfaceC1341j {
    @Override // p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final Object mo340a(Object obj) {
        ArrayList arrayList = new ArrayList();
        Iterator it = ((Iterable) obj).iterator();
        while (it.hasNext()) {
            arrayList.add(C1337f.m346b(it.next()));
        }
        return arrayList;
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i, p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final boolean mo341a(Class<?> cls) {
        return Collection.class.isAssignableFrom(cls);
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i
    /* renamed from: b */
    public final Object mo342b(Object obj, Type type) {
        Collection collection;
        if (!obj.getClass().equals(C5071a.class)) {
            return null;
        }
        Class<?> m4798c = C4195m.m4798c(type);
        C5071a c5071a = (C5071a) obj;
        if (m4798c == AbstractCollection.class) {
            collection = new ArrayList();
        } else if (m4798c.isAssignableFrom(HashSet.class)) {
            collection = new HashSet();
        } else if (m4798c.isAssignableFrom(LinkedHashSet.class)) {
            collection = new LinkedHashSet();
        } else if (m4798c.isAssignableFrom(TreeSet.class)) {
            collection = new TreeSet();
        } else if (m4798c.isAssignableFrom(ArrayList.class)) {
            collection = new ArrayList();
        } else if (m4798c.isAssignableFrom(EnumSet.class)) {
            collection = EnumSet.noneOf((Class) (type instanceof ParameterizedType ? ((ParameterizedType) type).getActualTypeArguments()[0] : Object.class));
        } else {
            try {
                collection = (Collection) m4798c.newInstance();
            } catch (Exception unused) {
                throw new IllegalArgumentException(C1499a.m623j(m4798c, new StringBuilder("create instane error, class ")));
            }
        }
        if (!(type instanceof ParameterizedType)) {
            throw new IllegalArgumentException("Does not support the implement for generics.");
        }
        Type type2 = ((ParameterizedType) type).getActualTypeArguments()[0];
        for (int i2 = 0; i2 < c5071a.m5700a(); i2++) {
            collection.add(C1336e.m343a(c5071a.m5701a(i2), type2));
        }
        return collection;
    }
}
