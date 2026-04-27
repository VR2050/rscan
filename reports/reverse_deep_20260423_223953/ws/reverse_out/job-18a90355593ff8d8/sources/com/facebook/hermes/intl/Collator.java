package com.facebook.hermes.intl;

import com.facebook.hermes.intl.a;
import com.facebook.hermes.intl.g;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class Collator {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private a.d f5836a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private a.c f5837b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f5838c;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f5840e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private a.b f5841f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private A0.b f5842g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private A0.b f5843h;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private String f5839d = "default";

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private a f5844i = new h();

    public Collator(List<String> list, Map<String, Object> map) throws A0.e {
        a(list, map);
        this.f5844i.f(this.f5842g).b(this.f5840e).a(this.f5841f).d(this.f5837b).g(this.f5838c);
    }

    private void a(List list, Map map) throws A0.e {
        g.a aVar = g.a.STRING;
        this.f5836a = (a.d) g.d(a.d.class, A0.d.h(g.c(map, "usage", aVar, A0.a.f20e, "sort")));
        Object objQ = A0.d.q();
        A0.d.c(objQ, "localeMatcher", g.c(map, "localeMatcher", aVar, A0.a.f16a, "best fit"));
        Object objC = g.c(map, "numeric", g.a.BOOLEAN, A0.d.d(), A0.d.d());
        if (!A0.d.n(objC)) {
            objC = A0.d.r(String.valueOf(A0.d.e(objC)));
        }
        A0.d.c(objQ, "kn", objC);
        A0.d.c(objQ, "kf", g.c(map, "caseFirst", aVar, A0.a.f19d, A0.d.d()));
        HashMap mapA = f.a(list, objQ, Arrays.asList("co", "kf", "kn"));
        A0.b bVar = (A0.b) A0.d.g(mapA).get("locale");
        this.f5842g = bVar;
        this.f5843h = bVar.e();
        Object objA = A0.d.a(mapA, "co");
        if (A0.d.j(objA)) {
            objA = A0.d.r("default");
        }
        this.f5839d = A0.d.h(objA);
        Object objA2 = A0.d.a(mapA, "kn");
        if (A0.d.j(objA2)) {
            this.f5840e = false;
        } else {
            this.f5840e = Boolean.parseBoolean(A0.d.h(objA2));
        }
        Object objA3 = A0.d.a(mapA, "kf");
        if (A0.d.j(objA3)) {
            objA3 = A0.d.r("false");
        }
        this.f5841f = (a.b) g.d(a.b.class, A0.d.h(objA3));
        if (this.f5836a == a.d.SEARCH) {
            ArrayList arrayListC = this.f5842g.c("collation");
            ArrayList arrayList = new ArrayList();
            Iterator it = arrayListC.iterator();
            while (it.hasNext()) {
                arrayList.add(A0.i.e((String) it.next()));
            }
            arrayList.add(A0.i.e("search"));
            this.f5842g.g("co", arrayList);
        }
        Object objC2 = g.c(map, "sensitivity", g.a.STRING, A0.a.f18c, A0.d.d());
        if (!A0.d.n(objC2)) {
            this.f5837b = (a.c) g.d(a.c.class, A0.d.h(objC2));
        } else if (this.f5836a == a.d.SORT) {
            this.f5837b = a.c.VARIANT;
        } else {
            this.f5837b = a.c.LOCALE;
        }
        this.f5838c = A0.d.e(g.c(map, "ignorePunctuation", g.a.BOOLEAN, A0.d.d(), Boolean.FALSE));
    }

    public static List<String> supportedLocalesOf(List<String> list, Map<String, Object> map) {
        return A0.d.h(g.c(map, "localeMatcher", g.a.STRING, A0.a.f16a, "best fit")).equals("best fit") ? Arrays.asList(e.d((String[]) list.toArray(new String[list.size()]))) : Arrays.asList(e.h((String[]) list.toArray(new String[list.size()])));
    }

    public double compare(String str, String str2) {
        return this.f5844i.c(str, str2);
    }

    public Map<String, Object> resolvedOptions() {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("locale", this.f5843h.a().replace("-kn-true", "-kn"));
        linkedHashMap.put("usage", this.f5836a.toString());
        a.c cVar = this.f5837b;
        if (cVar == a.c.LOCALE) {
            linkedHashMap.put("sensitivity", this.f5844i.e().toString());
        } else {
            linkedHashMap.put("sensitivity", cVar.toString());
        }
        linkedHashMap.put("ignorePunctuation", Boolean.valueOf(this.f5838c));
        linkedHashMap.put("collation", this.f5839d);
        linkedHashMap.put("numeric", Boolean.valueOf(this.f5840e));
        linkedHashMap.put("caseFirst", this.f5841f.toString());
        return linkedHashMap;
    }
}
