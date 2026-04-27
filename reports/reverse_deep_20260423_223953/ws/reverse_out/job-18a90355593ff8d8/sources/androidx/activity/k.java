package androidx.activity;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f2989a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0688a f2990b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Object f2991c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f2992d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f2993e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f2994f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final List f2995g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Runnable f2996h;

    public k(Executor executor, InterfaceC0688a interfaceC0688a) {
        t2.j.f(executor, "executor");
        t2.j.f(interfaceC0688a, "reportFullyDrawn");
        this.f2989a = executor;
        this.f2990b = interfaceC0688a;
        this.f2991c = new Object();
        this.f2995g = new ArrayList();
        this.f2996h = new Runnable() { // from class: androidx.activity.j
            @Override // java.lang.Runnable
            public final void run() {
                k.d(this.f2988b);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void d(k kVar) {
        t2.j.f(kVar, "this$0");
        synchronized (kVar.f2991c) {
            try {
                kVar.f2993e = false;
                if (kVar.f2992d == 0 && !kVar.f2994f) {
                    kVar.f2990b.a();
                    kVar.b();
                }
                h2.r rVar = h2.r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void b() {
        synchronized (this.f2991c) {
            try {
                this.f2994f = true;
                Iterator it = this.f2995g.iterator();
                while (it.hasNext()) {
                    ((InterfaceC0688a) it.next()).a();
                }
                this.f2995g.clear();
                h2.r rVar = h2.r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean c() {
        boolean z3;
        synchronized (this.f2991c) {
            z3 = this.f2994f;
        }
        return z3;
    }
}
