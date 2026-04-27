package p0;

import X.i;
import X.k;
import X.n;
import android.content.Context;
import android.graphics.drawable.Animatable;
import h0.AbstractC0548d;
import h0.C0550f;
import h0.C0552h;
import h0.InterfaceC0547c;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import u0.C0702a;
import v0.InterfaceC0705a;
import y0.InterfaceC0723b;

/* JADX INFO: renamed from: p0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0643b {

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private static final InterfaceC0645d f9811q = new a();

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private static final NullPointerException f9812r = new NullPointerException("No image request was specified!");

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private static final AtomicLong f9813s = new AtomicLong();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f9814a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Set f9815b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Set f9816c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Object f9817d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Object f9818e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Object f9819f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Object[] f9820g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f9821h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private n f9822i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private InterfaceC0645d f9823j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f9824k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f9825l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f9826m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f9827n = false;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private String f9828o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private InterfaceC0705a f9829p;

    /* JADX INFO: renamed from: p0.b$a */
    class a extends C0644c {
        a() {
        }

        @Override // p0.C0644c, p0.InterfaceC0645d
        public void k(String str, Object obj, Animatable animatable) {
            if (animatable != null) {
                animatable.start();
            }
        }
    }

    /* JADX INFO: renamed from: p0.b$b, reason: collision with other inner class name */
    class C0146b implements n {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ InterfaceC0705a f9830a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f9831b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Object f9832c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Object f9833d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ c f9834e;

        C0146b(InterfaceC0705a interfaceC0705a, String str, Object obj, Object obj2, c cVar) {
            this.f9830a = interfaceC0705a;
            this.f9831b = str;
            this.f9832c = obj;
            this.f9833d = obj2;
            this.f9834e = cVar;
        }

        @Override // X.n
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public InterfaceC0547c get() {
            return AbstractC0643b.this.g(this.f9830a, this.f9831b, this.f9832c, this.f9833d, this.f9834e);
        }

        public String toString() {
            return i.b(this).b("request", this.f9832c.toString()).toString();
        }
    }

    /* JADX INFO: renamed from: p0.b$c */
    public enum c {
        FULL_FETCH,
        DISK_CACHE,
        BITMAP_MEMORY_CACHE
    }

    protected AbstractC0643b(Context context, Set set, Set set2) {
        this.f9814a = context;
        this.f9815b = set;
        this.f9816c = set2;
        q();
    }

    protected static String c() {
        return String.valueOf(f9813s.getAndIncrement());
    }

    private void q() {
        this.f9817d = null;
        this.f9818e = null;
        this.f9819f = null;
        this.f9820g = null;
        this.f9821h = true;
        this.f9823j = null;
        this.f9824k = false;
        this.f9825l = false;
        this.f9827n = false;
        this.f9829p = null;
        this.f9828o = null;
    }

    public AbstractC0643b A(InterfaceC0645d interfaceC0645d) {
        this.f9823j = interfaceC0645d;
        return p();
    }

    public AbstractC0643b B(Object obj) {
        this.f9818e = obj;
        return p();
    }

    public AbstractC0643b C(Object obj) {
        this.f9819f = obj;
        return p();
    }

    public AbstractC0643b D(InterfaceC0705a interfaceC0705a) {
        this.f9829p = interfaceC0705a;
        return p();
    }

    protected void E() {
        boolean z3 = true;
        k.j(this.f9820g == null || this.f9818e == null, "Cannot specify both ImageRequest and FirstAvailableImageRequests!");
        if (this.f9822i != null && (this.f9820g != null || this.f9818e != null || this.f9819f != null)) {
            z3 = false;
        }
        k.j(z3, "Cannot specify DataSourceSupplier with other ImageRequests! Use one or the other.");
    }

    public AbstractC0642a a() {
        Object obj;
        E();
        if (this.f9818e == null && this.f9820g == null && (obj = this.f9819f) != null) {
            this.f9818e = obj;
            this.f9819f = null;
        }
        return b();
    }

    protected AbstractC0642a b() {
        if (U0.b.d()) {
            U0.b.a("AbstractDraweeControllerBuilder#buildController");
        }
        AbstractC0642a abstractC0642aV = v();
        abstractC0642aV.e0(r());
        abstractC0642aV.f0(o());
        abstractC0642aV.a0(e());
        f();
        abstractC0642aV.c0(null);
        u(abstractC0642aV);
        s(abstractC0642aV);
        if (U0.b.d()) {
            U0.b.b();
        }
        return abstractC0642aV;
    }

    public Object d() {
        return this.f9817d;
    }

    public String e() {
        return this.f9828o;
    }

    public InterfaceC0646e f() {
        return null;
    }

    protected abstract InterfaceC0547c g(InterfaceC0705a interfaceC0705a, String str, Object obj, Object obj2, c cVar);

    protected n h(InterfaceC0705a interfaceC0705a, String str, Object obj) {
        return i(interfaceC0705a, str, obj, c.FULL_FETCH);
    }

    protected n i(InterfaceC0705a interfaceC0705a, String str, Object obj, c cVar) {
        return new C0146b(interfaceC0705a, str, obj, d(), cVar);
    }

    protected n j(InterfaceC0705a interfaceC0705a, String str, Object[] objArr, boolean z3) {
        ArrayList arrayList = new ArrayList(objArr.length * 2);
        if (z3) {
            for (Object obj : objArr) {
                arrayList.add(i(interfaceC0705a, str, obj, c.BITMAP_MEMORY_CACHE));
            }
        }
        for (Object obj2 : objArr) {
            arrayList.add(h(interfaceC0705a, str, obj2));
        }
        return C0550f.b(arrayList);
    }

    public Object[] k() {
        return this.f9820g;
    }

    public Object l() {
        return this.f9818e;
    }

    public Object m() {
        return this.f9819f;
    }

    public InterfaceC0705a n() {
        return this.f9829p;
    }

    public boolean o() {
        return this.f9826m;
    }

    public boolean r() {
        return this.f9827n;
    }

    protected void s(AbstractC0642a abstractC0642a) {
        Set set = this.f9815b;
        if (set != null) {
            Iterator it = set.iterator();
            while (it.hasNext()) {
                abstractC0642a.k((InterfaceC0645d) it.next());
            }
        }
        Set set2 = this.f9816c;
        if (set2 != null) {
            Iterator it2 = set2.iterator();
            while (it2.hasNext()) {
                abstractC0642a.l((InterfaceC0723b) it2.next());
            }
        }
        InterfaceC0645d interfaceC0645d = this.f9823j;
        if (interfaceC0645d != null) {
            abstractC0642a.k(interfaceC0645d);
        }
        if (this.f9825l) {
            abstractC0642a.k(f9811q);
        }
    }

    protected void t(AbstractC0642a abstractC0642a) {
        if (abstractC0642a.v() == null) {
            abstractC0642a.d0(C0702a.c(this.f9814a));
        }
    }

    protected void u(AbstractC0642a abstractC0642a) {
        if (this.f9824k) {
            abstractC0642a.B().d(this.f9824k);
            t(abstractC0642a);
        }
    }

    protected abstract AbstractC0642a v();

    protected n w(InterfaceC0705a interfaceC0705a, String str) {
        n nVarJ;
        n nVar = this.f9822i;
        if (nVar != null) {
            return nVar;
        }
        Object obj = this.f9818e;
        if (obj != null) {
            nVarJ = h(interfaceC0705a, str, obj);
        } else {
            Object[] objArr = this.f9820g;
            nVarJ = objArr != null ? j(interfaceC0705a, str, objArr, this.f9821h) : null;
        }
        if (nVarJ != null && this.f9819f != null) {
            ArrayList arrayList = new ArrayList(2);
            arrayList.add(nVarJ);
            arrayList.add(h(interfaceC0705a, str, this.f9819f));
            nVarJ = C0552h.c(arrayList, false);
        }
        return nVarJ == null ? AbstractC0548d.a(f9812r) : nVarJ;
    }

    public AbstractC0643b x() {
        q();
        return p();
    }

    public AbstractC0643b y(boolean z3) {
        this.f9825l = z3;
        return p();
    }

    public AbstractC0643b z(Object obj) {
        this.f9817d = obj;
        return p();
    }

    protected final AbstractC0643b p() {
        return this;
    }
}
