package com.facebook.imagepipeline.producers;

import I0.InterfaceC0196v;
import T0.b;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0360e implements e0 {

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    public static final Set f6247o = X.h.a("id", "uri_source");

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    public static final Object f6248p = new Object();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final T0.b f6249b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f6250c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final String f6251d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final g0 f6252e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Object f6253f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final b.c f6254g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Map f6255h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f6256i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private H0.f f6257j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f6258k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f6259l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final List f6260m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final InterfaceC0196v f6261n;

    public C0360e(T0.b bVar, String str, g0 g0Var, Object obj, b.c cVar, boolean z3, boolean z4, H0.f fVar, InterfaceC0196v interfaceC0196v) {
        this(bVar, str, null, null, g0Var, obj, cVar, z3, z4, fVar, interfaceC0196v);
    }

    public static void c(List list) {
        if (list == null) {
            return;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            ((f0) it.next()).a();
        }
    }

    public static void e(List list) {
        if (list == null) {
            return;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            ((f0) it.next()).b();
        }
    }

    public static void f(List list) {
        if (list == null) {
            return;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            ((f0) it.next()).d();
        }
    }

    public static void g(List list) {
        if (list == null) {
            return;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            ((f0) it.next()).c();
        }
    }

    @Override // x0.InterfaceC0716a
    public void A(String str, Object obj) {
        if (f6247o.contains(str)) {
            return;
        }
        this.f6255h.put(str, obj);
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public void D(String str) {
        n0(str, "default");
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public g0 P() {
        return this.f6252e;
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public T0.b W() {
        return this.f6249b;
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public void Z(f0 f0Var) {
        boolean z3;
        synchronized (this) {
            this.f6260m.add(f0Var);
            z3 = this.f6259l;
        }
        if (z3) {
            f0Var.a();
        }
    }

    @Override // x0.InterfaceC0716a
    public Map b() {
        return this.f6255h;
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public synchronized boolean d0() {
        return this.f6258k;
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public b.c e0() {
        return this.f6254g;
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public InterfaceC0196v f0() {
        return this.f6261n;
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public String getId() {
        return this.f6250c;
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public Object i() {
        return this.f6253f;
    }

    public void j() {
        c(l());
    }

    public synchronized List l() {
        if (this.f6259l) {
            return null;
        }
        this.f6259l = true;
        return new ArrayList(this.f6260m);
    }

    public synchronized List m(boolean z3) {
        if (z3 == this.f6258k) {
            return null;
        }
        this.f6258k = z3;
        return new ArrayList(this.f6260m);
    }

    public synchronized List n(boolean z3) {
        if (z3 == this.f6256i) {
            return null;
        }
        this.f6256i = z3;
        return new ArrayList(this.f6260m);
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public void n0(String str, String str2) {
        this.f6255h.put("origin", str);
        this.f6255h.put("origin_sub", str2);
    }

    public synchronized List o(H0.f fVar) {
        if (fVar == this.f6257j) {
            return null;
        }
        this.f6257j = fVar;
        return new ArrayList(this.f6260m);
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public synchronized H0.f p() {
        return this.f6257j;
    }

    @Override // x0.InterfaceC0716a
    public void r(Map map) {
        if (map == null) {
            return;
        }
        for (Map.Entry entry : map.entrySet()) {
            A((String) entry.getKey(), entry.getValue());
        }
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public synchronized boolean v() {
        return this.f6256i;
    }

    @Override // x0.InterfaceC0716a
    public Object x(String str) {
        return this.f6255h.get(str);
    }

    @Override // com.facebook.imagepipeline.producers.e0
    public String y() {
        return this.f6251d;
    }

    public C0360e(T0.b bVar, String str, String str2, Map map, g0 g0Var, Object obj, b.c cVar, boolean z3, boolean z4, H0.f fVar, InterfaceC0196v interfaceC0196v) {
        this.f6249b = bVar;
        this.f6250c = str;
        HashMap map2 = new HashMap();
        this.f6255h = map2;
        map2.put("id", str);
        map2.put("uri_source", bVar == null ? "null-request" : bVar.v());
        r(map);
        this.f6251d = str2;
        this.f6252e = g0Var;
        this.f6253f = obj == null ? f6248p : obj;
        this.f6254g = cVar;
        this.f6256i = z3;
        this.f6257j = fVar;
        this.f6258k = z4;
        this.f6259l = false;
        this.f6260m = new ArrayList();
        this.f6261n = interfaceC0196v;
    }
}
