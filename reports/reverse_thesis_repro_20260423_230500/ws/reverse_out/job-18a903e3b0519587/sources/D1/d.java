package D1;

import android.util.Pair;
import c2.C0353a;
import java.util.LinkedHashMap;
import java.util.Map;
import t2.j;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class d extends P0.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f604a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Map f605b = new LinkedHashMap();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Map f606c = new LinkedHashMap();

    @Override // P0.e
    public void a(T0.b bVar, String str, Throwable th, boolean z3) {
        Pair pair;
        j.f(bVar, "request");
        j.f(str, "requestId");
        j.f(th, "throwable");
        if (C0353a.j(0L) && (pair = (Pair) this.f606c.get(str)) != null) {
            Object obj = pair.second;
            j.e(obj, "second");
            Object obj2 = pair.first;
            j.e(obj2, "first");
            C0353a.g(0L, (String) obj, ((Number) obj2).intValue());
            this.f606c.remove(str);
        }
    }

    @Override // P0.e
    public void b(T0.b bVar, Object obj, String str, boolean z3) {
        j.f(bVar, "request");
        j.f(obj, "callerContext");
        j.f(str, "requestId");
        if (C0353a.j(0L)) {
            StringBuilder sb = new StringBuilder();
            sb.append("FRESCO_REQUEST_");
            String string = bVar.v().toString();
            j.e(string, "toString(...)");
            sb.append(g.p(string, ':', '_', false, 4, null));
            Pair pairCreate = Pair.create(Integer.valueOf(this.f604a), sb.toString());
            Object obj2 = pairCreate.second;
            j.e(obj2, "second");
            C0353a.a(0L, (String) obj2, this.f604a);
            this.f606c.put(str, pairCreate);
            this.f604a++;
        }
    }

    @Override // P0.a, com.facebook.imagepipeline.producers.h0
    public boolean c(String str) {
        j.f(str, "requestId");
        return false;
    }

    @Override // P0.e
    public void d(T0.b bVar, String str, boolean z3) {
        Pair pair;
        j.f(bVar, "request");
        j.f(str, "requestId");
        if (C0353a.j(0L) && (pair = (Pair) this.f606c.get(str)) != null) {
            Object obj = pair.second;
            j.e(obj, "second");
            Object obj2 = pair.first;
            j.e(obj2, "first");
            C0353a.g(0L, (String) obj, ((Number) obj2).intValue());
            this.f606c.remove(str);
        }
    }

    @Override // P0.a, com.facebook.imagepipeline.producers.h0
    public void e(String str, String str2, String str3) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
        j.f(str3, "eventName");
        if (C0353a.j(0L)) {
            C0353a.n(0L, "FRESCO_PRODUCER_EVENT_" + g.p(str, ':', '_', false, 4, null) + "_" + g.p(str2, ':', '_', false, 4, null) + "_" + g.p(str3, ':', '_', false, 4, null), C0353a.EnumC0088a.f5682c);
        }
    }

    @Override // P0.a, com.facebook.imagepipeline.producers.h0
    public void f(String str, String str2, Map map) {
        Pair pair;
        j.f(str, "requestId");
        j.f(str2, "producerName");
        if (C0353a.j(0L) && (pair = (Pair) this.f605b.get(str)) != null) {
            Object obj = pair.second;
            j.e(obj, "second");
            Object obj2 = pair.first;
            j.e(obj2, "first");
            C0353a.g(0L, (String) obj, ((Number) obj2).intValue());
            this.f605b.remove(str);
        }
    }

    @Override // P0.a, com.facebook.imagepipeline.producers.h0
    public void g(String str, String str2) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
        if (C0353a.j(0L)) {
            Pair pairCreate = Pair.create(Integer.valueOf(this.f604a), "FRESCO_PRODUCER_" + g.p(str2, ':', '_', false, 4, null));
            Object obj = pairCreate.second;
            j.e(obj, "second");
            C0353a.a(0L, (String) obj, this.f604a);
            this.f605b.put(str, pairCreate);
            this.f604a++;
        }
    }

    @Override // P0.a, com.facebook.imagepipeline.producers.h0
    public void h(String str, String str2, Throwable th, Map map) {
        Pair pair;
        j.f(str, "requestId");
        j.f(str2, "producerName");
        j.f(th, "t");
        if (C0353a.j(0L) && (pair = (Pair) this.f605b.get(str)) != null) {
            Object obj = pair.second;
            j.e(obj, "second");
            Object obj2 = pair.first;
            j.e(obj2, "first");
            C0353a.g(0L, (String) obj, ((Number) obj2).intValue());
            this.f605b.remove(str);
        }
    }

    @Override // P0.a, com.facebook.imagepipeline.producers.h0
    public void i(String str, String str2, Map map) {
        Pair pair;
        j.f(str, "requestId");
        j.f(str2, "producerName");
        if (C0353a.j(0L) && (pair = (Pair) this.f605b.get(str)) != null) {
            Object obj = pair.second;
            j.e(obj, "second");
            Object obj2 = pair.first;
            j.e(obj2, "first");
            C0353a.g(0L, (String) obj, ((Number) obj2).intValue());
            this.f605b.remove(str);
        }
    }

    @Override // P0.e
    public void j(String str) {
        Pair pair;
        j.f(str, "requestId");
        if (C0353a.j(0L) && (pair = (Pair) this.f606c.get(str)) != null) {
            Object obj = pair.second;
            j.e(obj, "second");
            Object obj2 = pair.first;
            j.e(obj2, "first");
            C0353a.g(0L, (String) obj, ((Number) obj2).intValue());
            this.f606c.remove(str);
        }
    }
}
