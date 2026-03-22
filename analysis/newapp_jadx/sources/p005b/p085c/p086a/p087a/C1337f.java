package p005b.p085c.p086a.p087a;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.json.alipay.C5071a;
import org.json.alipay.C5072b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.a.a.f */
/* loaded from: classes.dex */
public final class C1337f {

    /* renamed from: a */
    public static List<InterfaceC1341j> f1144a;

    static {
        ArrayList arrayList = new ArrayList();
        f1144a = arrayList;
        arrayList.add(new C1343l());
        f1144a.add(new C1335d());
        f1144a.add(new C1334c());
        f1144a.add(new C1339h());
        f1144a.add(new C1333b());
        f1144a.add(new C1332a());
        f1144a.add(new C1338g());
    }

    /* renamed from: a */
    public static String m345a(Object obj) {
        if (obj == null) {
            return null;
        }
        Object m346b = m346b(obj);
        if (C4195m.m4820n(m346b.getClass())) {
            return C5072b.m5704c(m346b.toString());
        }
        if (Collection.class.isAssignableFrom(m346b.getClass())) {
            return new C5071a((Collection) m346b).toString();
        }
        if (Map.class.isAssignableFrom(m346b.getClass())) {
            return new C5072b((Map) m346b).toString();
        }
        throw new IllegalArgumentException("Unsupported Class : " + m346b.getClass());
    }

    /* renamed from: b */
    public static Object m346b(Object obj) {
        Object mo340a;
        if (obj == null) {
            return null;
        }
        for (InterfaceC1341j interfaceC1341j : f1144a) {
            if (interfaceC1341j.mo341a(obj.getClass()) && (mo340a = interfaceC1341j.mo340a(obj)) != null) {
                return mo340a;
            }
        }
        throw new IllegalArgumentException("Unsupported Class : " + obj.getClass());
    }
}
