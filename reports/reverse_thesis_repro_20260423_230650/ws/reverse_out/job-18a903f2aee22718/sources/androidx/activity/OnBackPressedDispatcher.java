package androidx.activity;

import android.os.Build;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;
import androidx.activity.OnBackPressedDispatcher;
import androidx.lifecycle.f;
import i2.C0579g;
import java.util.Iterator;
import java.util.ListIterator;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class OnBackPressedDispatcher {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Runnable f2964a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0579g f2965b = new C0579g();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private InterfaceC0688a f2966c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private OnBackInvokedCallback f2967d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private OnBackInvokedDispatcher f2968e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f2969f;

    private final class LifecycleOnBackPressedCancellable implements androidx.lifecycle.i, androidx.activity.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final androidx.lifecycle.f f2970a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final m f2971b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private androidx.activity.a f2972c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ OnBackPressedDispatcher f2973d;

        public LifecycleOnBackPressedCancellable(OnBackPressedDispatcher onBackPressedDispatcher, androidx.lifecycle.f fVar, m mVar) {
            t2.j.f(fVar, "lifecycle");
            t2.j.f(mVar, "onBackPressedCallback");
            this.f2973d = onBackPressedDispatcher;
            this.f2970a = fVar;
            this.f2971b = mVar;
            fVar.a(this);
        }

        @Override // androidx.activity.a
        public void cancel() {
            this.f2970a.c(this);
            this.f2971b.e(this);
            androidx.activity.a aVar = this.f2972c;
            if (aVar != null) {
                aVar.cancel();
            }
            this.f2972c = null;
        }

        @Override // androidx.lifecycle.i
        public void d(androidx.lifecycle.k kVar, f.a aVar) {
            t2.j.f(kVar, "source");
            t2.j.f(aVar, "event");
            if (aVar == f.a.ON_START) {
                this.f2972c = this.f2973d.c(this.f2971b);
                return;
            }
            if (aVar != f.a.ON_STOP) {
                if (aVar == f.a.ON_DESTROY) {
                    cancel();
                }
            } else {
                androidx.activity.a aVar2 = this.f2972c;
                if (aVar2 != null) {
                    aVar2.cancel();
                }
            }
        }
    }

    static final class a extends t2.k implements InterfaceC0688a {
        a() {
            super(0);
        }

        @Override // s2.InterfaceC0688a
        public /* bridge */ /* synthetic */ Object a() {
            e();
            return h2.r.f9288a;
        }

        public final void e() {
            OnBackPressedDispatcher.this.g();
        }
    }

    static final class b extends t2.k implements InterfaceC0688a {
        b() {
            super(0);
        }

        @Override // s2.InterfaceC0688a
        public /* bridge */ /* synthetic */ Object a() {
            e();
            return h2.r.f9288a;
        }

        public final void e() {
            OnBackPressedDispatcher.this.e();
        }
    }

    public static final class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final c f2976a = new c();

        private c() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final void c(InterfaceC0688a interfaceC0688a) {
            t2.j.f(interfaceC0688a, "$onBackInvoked");
            interfaceC0688a.a();
        }

        public final OnBackInvokedCallback b(final InterfaceC0688a interfaceC0688a) {
            t2.j.f(interfaceC0688a, "onBackInvoked");
            return new OnBackInvokedCallback() { // from class: androidx.activity.n
                @Override // android.window.OnBackInvokedCallback
                public final void onBackInvoked() {
                    OnBackPressedDispatcher.c.c(interfaceC0688a);
                }
            };
        }

        public final void d(Object obj, int i3, Object obj2) {
            t2.j.f(obj, "dispatcher");
            t2.j.f(obj2, "callback");
            ((OnBackInvokedDispatcher) obj).registerOnBackInvokedCallback(i3, (OnBackInvokedCallback) obj2);
        }

        public final void e(Object obj, Object obj2) {
            t2.j.f(obj, "dispatcher");
            t2.j.f(obj2, "callback");
            ((OnBackInvokedDispatcher) obj).unregisterOnBackInvokedCallback((OnBackInvokedCallback) obj2);
        }
    }

    private final class d implements androidx.activity.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final m f2977a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ OnBackPressedDispatcher f2978b;

        public d(OnBackPressedDispatcher onBackPressedDispatcher, m mVar) {
            t2.j.f(mVar, "onBackPressedCallback");
            this.f2978b = onBackPressedDispatcher;
            this.f2977a = mVar;
        }

        @Override // androidx.activity.a
        public void cancel() {
            this.f2978b.f2965b.remove(this.f2977a);
            this.f2977a.e(this);
            if (Build.VERSION.SDK_INT >= 33) {
                this.f2977a.g(null);
                this.f2978b.g();
            }
        }
    }

    public OnBackPressedDispatcher(Runnable runnable) {
        this.f2964a = runnable;
        if (Build.VERSION.SDK_INT >= 33) {
            this.f2966c = new a();
            this.f2967d = c.f2976a.b(new b());
        }
    }

    public final void b(androidx.lifecycle.k kVar, m mVar) {
        t2.j.f(kVar, "owner");
        t2.j.f(mVar, "onBackPressedCallback");
        androidx.lifecycle.f fVarS = kVar.s();
        if (fVarS.b() == f.b.DESTROYED) {
            return;
        }
        mVar.a(new LifecycleOnBackPressedCancellable(this, fVarS, mVar));
        if (Build.VERSION.SDK_INT >= 33) {
            g();
            mVar.g(this.f2966c);
        }
    }

    public final androidx.activity.a c(m mVar) {
        t2.j.f(mVar, "onBackPressedCallback");
        this.f2965b.add(mVar);
        d dVar = new d(this, mVar);
        mVar.a(dVar);
        if (Build.VERSION.SDK_INT >= 33) {
            g();
            mVar.g(this.f2966c);
        }
        return dVar;
    }

    public final boolean d() {
        C0579g c0579g = this.f2965b;
        if (c0579g != null && c0579g.isEmpty()) {
            return false;
        }
        Iterator<E> it = c0579g.iterator();
        while (it.hasNext()) {
            if (((m) it.next()).c()) {
                return true;
            }
        }
        return false;
    }

    public final void e() {
        Object objPrevious;
        C0579g c0579g = this.f2965b;
        ListIterator<E> listIterator = c0579g.listIterator(c0579g.size());
        while (true) {
            if (!listIterator.hasPrevious()) {
                objPrevious = null;
                break;
            } else {
                objPrevious = listIterator.previous();
                if (((m) objPrevious).c()) {
                    break;
                }
            }
        }
        m mVar = (m) objPrevious;
        if (mVar != null) {
            mVar.b();
            return;
        }
        Runnable runnable = this.f2964a;
        if (runnable != null) {
            runnable.run();
        }
    }

    public final void f(OnBackInvokedDispatcher onBackInvokedDispatcher) {
        t2.j.f(onBackInvokedDispatcher, "invoker");
        this.f2968e = onBackInvokedDispatcher;
        g();
    }

    public final void g() {
        boolean zD = d();
        OnBackInvokedDispatcher onBackInvokedDispatcher = this.f2968e;
        OnBackInvokedCallback onBackInvokedCallback = this.f2967d;
        if (onBackInvokedDispatcher == null || onBackInvokedCallback == null) {
            return;
        }
        if (zD && !this.f2969f) {
            c.f2976a.d(onBackInvokedDispatcher, 0, onBackInvokedCallback);
            this.f2969f = true;
        } else {
            if (zD || !this.f2969f) {
                return;
            }
            c.f2976a.e(onBackInvokedDispatcher, onBackInvokedCallback);
            this.f2969f = false;
        }
    }
}
