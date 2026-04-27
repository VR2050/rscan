package W1;

import I0.C0194t;
import I0.y;
import java.util.Iterator;
import java.util.List;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final b f2837a = new b();

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final W1.a f2838a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final W1.a f2839b;

        public a(W1.a aVar, W1.a aVar2) {
            this.f2838a = aVar;
            this.f2839b = aVar2;
        }
    }

    private b() {
    }

    public static final a a(int i3, int i4, List list) {
        j.f(list, "sources");
        return b(i3, i4, list, 1.0d);
    }

    public static final a b(int i3, int i4, List list, double d3) {
        j.f(list, "sources");
        if (list.isEmpty()) {
            return new a(null, null);
        }
        if (list.size() == 1) {
            return new a((W1.a) list.get(0), null);
        }
        if (i3 <= 0 || i4 <= 0) {
            return new a(null, null);
        }
        C0194t c0194tJ = y.l().j();
        j.e(c0194tJ, "getImagePipeline(...)");
        double d4 = ((double) (i3 * i4)) * d3;
        Iterator it = list.iterator();
        double d5 = Double.MAX_VALUE;
        double d6 = Double.MAX_VALUE;
        W1.a aVar = null;
        W1.a aVar2 = null;
        while (it.hasNext()) {
            W1.a aVar3 = (W1.a) it.next();
            double dAbs = Math.abs(1.0d - (aVar3.d() / d4));
            if (dAbs < d5) {
                aVar2 = aVar3;
                d5 = dAbs;
            }
            if (dAbs < d6 && aVar3.c() != D1.a.f594c && (c0194tJ.r(aVar3.f()) || c0194tJ.t(aVar3.f()))) {
                aVar = aVar3;
                d6 = dAbs;
            }
        }
        return new a(aVar2, (aVar == null || aVar2 == null || !j.b(aVar.e(), aVar2.e())) ? aVar : null);
    }
}
