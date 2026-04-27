package I0;

import T0.b;
import android.net.Uri;
import android.os.StrictMode;
import com.facebook.imagepipeline.producers.d0;
import com.facebook.imagepipeline.producers.l0;
import com.facebook.imagepipeline.producers.p0;
import h0.AbstractC0548d;
import h0.InterfaceC0547c;
import h2.C0562h;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: I0.t, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0194t {

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public static final a f1230n = new a(null);

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final CancellationException f1231o = new CancellationException("Prefetching is not enabled");

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final CancellationException f1232p = new CancellationException("ImageRequest is null");

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private static final CancellationException f1233q = new CancellationException("Modified URL is null");

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final W f1234a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final X.n f1235b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final X.n f1236c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final P0.e f1237d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final P0.d f1238e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final G0.x f1239f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final G0.x f1240g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final G0.k f1241h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final p0 f1242i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final X.n f1243j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final AtomicLong f1244k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final X.n f1245l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final InterfaceC0196v f1246m;

    /* JADX INFO: renamed from: I0.t$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: renamed from: I0.t$b */
    public /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f1247a;

        static {
            int[] iArr = new int[b.EnumC0041b.values().length];
            try {
                iArr[b.EnumC0041b.DEFAULT.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[b.EnumC0041b.SMALL.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[b.EnumC0041b.DYNAMIC.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            f1247a = iArr;
        }
    }

    public C0194t(W w3, Set set, Set set2, X.n nVar, G0.x xVar, G0.x xVar2, X.n nVar2, G0.k kVar, p0 p0Var, X.n nVar3, X.n nVar4, T.a aVar, InterfaceC0196v interfaceC0196v) {
        t2.j.f(w3, "producerSequenceFactory");
        t2.j.f(set, "requestListeners");
        t2.j.f(set2, "requestListener2s");
        t2.j.f(nVar, "isPrefetchEnabledSupplier");
        t2.j.f(xVar, "bitmapMemoryCache");
        t2.j.f(xVar2, "encodedMemoryCache");
        t2.j.f(nVar2, "diskCachesStoreSupplier");
        t2.j.f(kVar, "cacheKeyFactory");
        t2.j.f(p0Var, "threadHandoffProducerQueue");
        t2.j.f(nVar3, "suppressBitmapPrefetchingSupplier");
        t2.j.f(nVar4, "lazyDataSource");
        t2.j.f(interfaceC0196v, "config");
        this.f1234a = w3;
        this.f1235b = nVar;
        this.f1236c = nVar2;
        this.f1237d = new P0.c(set);
        this.f1238e = new P0.b(set2);
        this.f1244k = new AtomicLong();
        this.f1239f = xVar;
        this.f1240g = xVar2;
        this.f1241h = kVar;
        this.f1242i = p0Var;
        this.f1243j = nVar3;
        this.f1245l = nVar4;
        this.f1246m = interfaceC0196v;
    }

    private final InterfaceC0547c A(d0 d0Var, T0.b bVar, b.c cVar, Object obj, P0.e eVar, String str) {
        return B(d0Var, bVar, cVar, obj, eVar, str, null);
    }

    private final InterfaceC0547c B(d0 d0Var, T0.b bVar, b.c cVar, Object obj, P0.e eVar, String str, Map map) {
        InterfaceC0547c interfaceC0547cB;
        if (!U0.b.d()) {
            com.facebook.imagepipeline.producers.F f3 = new com.facebook.imagepipeline.producers.F(q(bVar, eVar), this.f1238e);
            try {
                b.c cVarA = b.c.a(bVar.k(), cVar);
                t2.j.e(cVarA, "getMax(...)");
                l0 l0Var = new l0(bVar, n(), str, f3, obj, cVarA, false, bVar.p() || !f0.f.n(bVar.v()), bVar.o(), this.f1246m);
                l0Var.r(map);
                return J0.b.I(d0Var, l0Var, f3);
            } catch (Exception e3) {
                return AbstractC0548d.b(e3);
            }
        }
        U0.b.a("ImagePipeline#submitFetchRequest");
        try {
            com.facebook.imagepipeline.producers.F f4 = new com.facebook.imagepipeline.producers.F(q(bVar, eVar), this.f1238e);
            try {
                b.c cVarA2 = b.c.a(bVar.k(), cVar);
                t2.j.e(cVarA2, "getMax(...)");
                l0 l0Var2 = new l0(bVar, n(), str, f4, obj, cVarA2, false, bVar.p() || !f0.f.n(bVar.v()), bVar.o(), this.f1246m);
                l0Var2.r(map);
                interfaceC0547cB = J0.b.I(d0Var, l0Var2, f4);
            } catch (Exception e4) {
                interfaceC0547cB = AbstractC0548d.b(e4);
            }
            U0.b.b();
            return interfaceC0547cB;
        } catch (Throwable th) {
            U0.b.b();
            throw th;
        }
    }

    private final InterfaceC0547c C(d0 d0Var, T0.b bVar, b.c cVar, Object obj, H0.f fVar, P0.e eVar) {
        T0.b bVarA = bVar;
        com.facebook.imagepipeline.producers.F f3 = new com.facebook.imagepipeline.producers.F(q(bVar, eVar), this.f1238e);
        Uri uriV = bVar.v();
        t2.j.e(uriV, "getSourceUri(...)");
        Uri uriA = z0.b.f10538b.a(uriV, obj);
        if (uriA == null) {
            InterfaceC0547c interfaceC0547cB = AbstractC0548d.b(f1233q);
            t2.j.e(interfaceC0547cB, "immediateFailedDataSource(...)");
            return interfaceC0547cB;
        }
        if (!t2.j.b(uriV, uriA)) {
            bVarA = T0.c.b(bVar).R(uriA).a();
        }
        T0.b bVar2 = bVarA;
        try {
            b.c cVarA = b.c.a(bVar2.k(), cVar);
            t2.j.e(cVarA, "getMax(...)");
            String strN = n();
            x xVarG = this.f1246m.G();
            return J0.c.f1454j.a(d0Var, new l0(bVar2, strN, f3, obj, cVarA, true, xVarG != null && xVarG.b() && bVar2.p(), fVar, this.f1246m), f3);
        } catch (Exception e3) {
            return AbstractC0548d.b(e3);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean f(R.d dVar) {
        t2.j.f(dVar, "it");
        return true;
    }

    public static /* synthetic */ InterfaceC0547c m(C0194t c0194t, T0.b bVar, Object obj, b.c cVar, P0.e eVar, String str, int i3, Object obj2) {
        return c0194t.l(bVar, obj, (i3 & 4) != 0 ? null : cVar, (i3 & 8) != 0 ? null : eVar, (i3 & 16) != 0 ? null : str);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final boolean v(T0.b bVar) {
        Object obj = this.f1236c.get();
        t2.j.e(obj, "get(...)");
        InterfaceC0178c interfaceC0178c = (InterfaceC0178c) obj;
        R.d dVarA = this.f1241h.a(bVar, null);
        String strF = bVar.f();
        if (strF != null) {
            G0.j jVar = (G0.j) interfaceC0178c.b().get(strF);
            if (jVar == null) {
                return false;
            }
            t2.j.c(dVarA);
            return jVar.k(dVarA);
        }
        Iterator it = interfaceC0178c.b().entrySet().iterator();
        while (it.hasNext()) {
            G0.j jVar2 = (G0.j) ((Map.Entry) it.next()).getValue();
            t2.j.c(dVarA);
            if (jVar2.k(dVarA)) {
                return true;
            }
        }
        return false;
    }

    private final X.l w(final Uri uri) {
        return new X.l() { // from class: I0.r
            @Override // X.l
            public final boolean a(Object obj) {
                return C0194t.x(uri, (R.d) obj);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean x(Uri uri, R.d dVar) {
        t2.j.f(uri, "$uri");
        t2.j.f(dVar, "key");
        return dVar.b(uri);
    }

    public final void c() {
        e();
        d();
    }

    public final void d() {
        Object obj = this.f1236c.get();
        t2.j.e(obj, "get(...)");
        InterfaceC0178c interfaceC0178c = (InterfaceC0178c) obj;
        interfaceC0178c.a().h();
        interfaceC0178c.c().h();
        Iterator it = interfaceC0178c.b().entrySet().iterator();
        while (it.hasNext()) {
            ((G0.j) ((Map.Entry) it.next()).getValue()).h();
        }
    }

    public final void e() {
        X.l lVar = new X.l() { // from class: I0.s
            @Override // X.l
            public final boolean a(Object obj) {
                return C0194t.f((R.d) obj);
            }
        };
        this.f1239f.e(lVar);
        this.f1240g.e(lVar);
    }

    public final void g(Uri uri) {
        t2.j.f(uri, "uri");
        j(uri);
        i(uri);
    }

    public final void h(T0.b bVar) {
        if (bVar == null) {
            return;
        }
        R.d dVarA = this.f1241h.a(bVar, null);
        Object obj = this.f1236c.get();
        t2.j.e(obj, "get(...)");
        InterfaceC0178c interfaceC0178c = (InterfaceC0178c) obj;
        G0.j jVarA = interfaceC0178c.a();
        t2.j.c(dVarA);
        jVarA.s(dVarA);
        interfaceC0178c.c().s(dVarA);
        Iterator it = interfaceC0178c.b().entrySet().iterator();
        while (it.hasNext()) {
            ((G0.j) ((Map.Entry) it.next()).getValue()).s(dVarA);
        }
    }

    public final void i(Uri uri) {
        T0.b bVarA = T0.b.a(uri);
        if (bVarA == null) {
            throw new IllegalStateException("Required value was null.");
        }
        h(bVarA);
    }

    public final void j(Uri uri) {
        t2.j.f(uri, "uri");
        X.l lVarW = w(uri);
        this.f1239f.e(lVarW);
        this.f1240g.e(lVarW);
    }

    public final InterfaceC0547c k(T0.b bVar, Object obj) {
        return m(this, bVar, obj, null, null, null, 24, null);
    }

    public final InterfaceC0547c l(T0.b bVar, Object obj, b.c cVar, P0.e eVar, String str) {
        if (bVar == null) {
            InterfaceC0547c interfaceC0547cB = AbstractC0548d.b(new NullPointerException());
            t2.j.e(interfaceC0547cB, "immediateFailedDataSource(...)");
            return interfaceC0547cB;
        }
        try {
            d0 d0VarE = this.f1234a.E(bVar);
            if (cVar == null) {
                cVar = b.c.FULL_FETCH;
            }
            return A(d0VarE, bVar, cVar, obj, eVar, str);
        } catch (Exception e3) {
            return AbstractC0548d.b(e3);
        }
    }

    public final String n() {
        return String.valueOf(this.f1244k.getAndIncrement());
    }

    public final G0.x o() {
        return this.f1239f;
    }

    public final G0.k p() {
        return this.f1241h;
    }

    public final P0.e q(T0.b bVar, P0.e eVar) {
        if (bVar != null) {
            return eVar == null ? bVar.q() == null ? this.f1237d : new P0.c(this.f1237d, bVar.q()) : bVar.q() == null ? new P0.c(this.f1237d, eVar) : new P0.c(this.f1237d, eVar, bVar.q());
        }
        throw new IllegalStateException("Required value was null.");
    }

    public final boolean r(Uri uri) {
        if (uri == null) {
            return false;
        }
        return this.f1239f.d(w(uri));
    }

    public final boolean s(T0.b bVar) {
        boolean zK;
        t2.j.f(bVar, "imageRequest");
        Object obj = this.f1236c.get();
        t2.j.e(obj, "get(...)");
        InterfaceC0178c interfaceC0178c = (InterfaceC0178c) obj;
        R.d dVarA = this.f1241h.a(bVar, null);
        b.EnumC0041b enumC0041bC = bVar.c();
        t2.j.e(enumC0041bC, "getCacheChoice(...)");
        StrictMode.ThreadPolicy threadPolicyAllowThreadDiskReads = StrictMode.allowThreadDiskReads();
        try {
            int i3 = b.f1247a[enumC0041bC.ordinal()];
            if (i3 == 1) {
                G0.j jVarA = interfaceC0178c.a();
                t2.j.c(dVarA);
                zK = jVarA.k(dVarA);
            } else if (i3 == 2) {
                G0.j jVarC = interfaceC0178c.c();
                t2.j.c(dVarA);
                zK = jVarC.k(dVarA);
            } else {
                if (i3 != 3) {
                    throw new C0562h();
                }
                zK = v(bVar);
            }
            StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskReads);
            return zK;
        } catch (Throwable th) {
            StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskReads);
            throw th;
        }
    }

    public final boolean t(Uri uri) {
        return u(uri, b.EnumC0041b.SMALL) || u(uri, b.EnumC0041b.DEFAULT) || u(uri, b.EnumC0041b.DYNAMIC);
    }

    public final boolean u(Uri uri, b.EnumC0041b enumC0041b) {
        T0.b bVarA = T0.c.x(uri).A(enumC0041b).a();
        t2.j.c(bVarA);
        return s(bVarA);
    }

    public final InterfaceC0547c y(T0.b bVar, Object obj) {
        return z(bVar, obj, H0.f.f1016d, null);
    }

    public final InterfaceC0547c z(T0.b bVar, Object obj, H0.f fVar, P0.e eVar) {
        t2.j.f(fVar, "priority");
        if (!((Boolean) this.f1235b.get()).booleanValue()) {
            InterfaceC0547c interfaceC0547cB = AbstractC0548d.b(f1231o);
            t2.j.e(interfaceC0547cB, "immediateFailedDataSource(...)");
            return interfaceC0547cB;
        }
        if (bVar == null) {
            InterfaceC0547c interfaceC0547cB2 = AbstractC0548d.b(new NullPointerException("imageRequest is null"));
            t2.j.c(interfaceC0547cB2);
            return interfaceC0547cB2;
        }
        try {
            return C(this.f1234a.G(bVar), bVar, b.c.FULL_FETCH, obj, fVar, eVar);
        } catch (Exception e3) {
            return AbstractC0548d.b(e3);
        }
    }
}
