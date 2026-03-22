package p005b.p085c.p086a.p087a;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import org.json.alipay.C5071a;
import org.json.alipay.C5072b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.a.a.e */
/* loaded from: classes.dex */
public final class C1336e {

    /* renamed from: a */
    public static List<InterfaceC1340i> f1143a;

    static {
        ArrayList arrayList = new ArrayList();
        f1143a = arrayList;
        arrayList.add(new C1343l());
        f1143a.add(new C1335d());
        f1143a.add(new C1334c());
        f1143a.add(new C1339h());
        f1143a.add(new C1342k());
        f1143a.add(new C1333b());
        f1143a.add(new C1332a());
        f1143a.add(new C1338g());
    }

    /* renamed from: a */
    public static final <T> T m343a(Object obj, Type type) {
        T t;
        for (InterfaceC1340i interfaceC1340i : f1143a) {
            if (interfaceC1340i.mo341a(C4195m.m4798c(type)) && (t = (T) interfaceC1340i.mo342b(obj, type)) != null) {
                return t;
            }
        }
        return null;
    }

    /* renamed from: b */
    public static final Object m344b(String str, Type type) {
        Object c5072b;
        if (str == null || str.length() == 0) {
            return null;
        }
        String trim = str.trim();
        if (trim.startsWith("[") && trim.endsWith("]")) {
            c5072b = new C5071a(trim);
        } else {
            if (!trim.startsWith("{") || !trim.endsWith("}")) {
                return m343a(trim, type);
            }
            c5072b = new C5072b(trim);
        }
        return m343a(c5072b, type);
    }
}
