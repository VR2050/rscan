package com.facebook.hermes.intl;

import com.facebook.hermes.intl.e;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public abstract class f {
    public static HashMap a(List list, Object obj, List list2) {
        HashMap map = new HashMap();
        e.a aVarF = A0.d.h(A0.d.a(obj, "localeMatcher")).equals("lookup") ? e.f((String[]) list.toArray(new String[list.size()])) : e.c((String[]) list.toArray(new String[list.size()]));
        HashSet<String> hashSet = new HashSet();
        Iterator it = list2.iterator();
        while (it.hasNext()) {
            String str = (String) it.next();
            Object objB = A0.d.b();
            Object obj2 = objB;
            if (!aVarF.f6026b.isEmpty()) {
                obj2 = objB;
                if (aVarF.f6026b.containsKey(str)) {
                    String str2 = (String) aVarF.f6026b.get(str);
                    boolean zIsEmpty = str2.isEmpty();
                    Object objR = str2;
                    if (zIsEmpty) {
                        objR = A0.d.r("true");
                    }
                    hashSet.add(str);
                    obj2 = objR;
                }
            }
            Object obj3 = obj2;
            if (A0.d.g(obj).containsKey(str)) {
                Object objA = A0.d.a(obj, str);
                boolean zM = A0.d.m(objA);
                Object objO = objA;
                if (zM) {
                    boolean zIsEmpty2 = A0.d.h(objA).isEmpty();
                    objO = objA;
                    if (zIsEmpty2) {
                        objO = A0.d.o(true);
                    }
                }
                obj3 = obj2;
                if (!A0.d.n(objO)) {
                    boolean zEquals = objO.equals(obj2);
                    obj3 = obj2;
                    if (!zEquals) {
                        hashSet.remove(str);
                        obj3 = objO;
                    }
                }
            }
            boolean zJ = A0.d.j(obj3);
            Object objF = obj3;
            if (!zJ) {
                objF = A0.i.f(str, obj3);
            }
            if (!A0.d.m(objF) || A0.i.c(str, A0.d.h(objF), aVarF.f6025a)) {
                map.put(str, objF);
            } else {
                map.put(str, A0.d.b());
            }
        }
        for (String str3 : hashSet) {
            ArrayList arrayList = new ArrayList();
            String strH = A0.d.h(A0.i.f(str3, A0.d.r((String) aVarF.f6026b.get(str3))));
            if (!A0.d.m(strH) || A0.i.c(str3, A0.d.h(strH), aVarF.f6025a)) {
                arrayList.add(strH);
                aVarF.f6025a.g(str3, arrayList);
            }
        }
        map.put("locale", aVarF.f6025a);
        return map;
    }
}
