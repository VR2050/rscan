package com.facebook.react.modules.core;

import android.util.SparseArray;
import android.view.Choreographer;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.modules.core.JavaTimerManager;
import com.facebook.react.modules.core.b;
import d1.l;
import h2.r;
import java.util.Comparator;
import java.util.Iterator;
import java.util.PriorityQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.p;
import t1.C0696c;
import t1.InterfaceC0697d;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class JavaTimerManager implements LifecycleEventListener, InterfaceC0697d {

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private static final a f7015r = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ReactApplicationContext f7016b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final A1.c f7017c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final com.facebook.react.modules.core.b f7018d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final j1.e f7019e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Object f7020f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final Object f7021g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final SparseArray f7022h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final AtomicBoolean f7023i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final AtomicBoolean f7024j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final e f7025k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final c f7026l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private b f7027m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f7028n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f7029o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private boolean f7030p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final PriorityQueue f7031q;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean b(d dVar, long j3) {
            return !dVar.b() && ((long) dVar.a()) < j3;
        }

        private a() {
        }
    }

    private final class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final long f7032b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private volatile boolean f7033c;

        public b(long j3) {
            this.f7032b = j3;
        }

        public final void a() {
            this.f7033c = true;
        }

        @Override // java.lang.Runnable
        public void run() {
            boolean z3;
            if (this.f7033c) {
                return;
            }
            long jC = l.c() - (this.f7032b / ((long) 1000000));
            long jA = l.a() - jC;
            if (16.666666f - jC < 1.0f) {
                return;
            }
            Object obj = JavaTimerManager.this.f7021g;
            JavaTimerManager javaTimerManager = JavaTimerManager.this;
            synchronized (obj) {
                z3 = javaTimerManager.f7030p;
                r rVar = r.f9288a;
            }
            if (z3) {
                JavaTimerManager.this.f7017c.callIdleCallbacks(jA);
            }
            JavaTimerManager.this.f7027m = null;
        }
    }

    private final class c implements Choreographer.FrameCallback {
        public c() {
        }

        @Override // android.view.Choreographer.FrameCallback
        public void doFrame(long j3) {
            if (!JavaTimerManager.this.f7023i.get() || JavaTimerManager.this.f7024j.get()) {
                b bVar = JavaTimerManager.this.f7027m;
                if (bVar != null) {
                    bVar.a();
                }
                JavaTimerManager javaTimerManager = JavaTimerManager.this;
                javaTimerManager.f7027m = javaTimerManager.new b(j3);
                JavaTimerManager.this.f7016b.runOnJSQueueThread(JavaTimerManager.this.f7027m);
                JavaTimerManager.this.f7018d.k(b.a.f7053g, this);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static final class d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f7036a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private long f7037b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f7038c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final boolean f7039d;

        public d(int i3, long j3, int i4, boolean z3) {
            this.f7036a = i3;
            this.f7037b = j3;
            this.f7038c = i4;
            this.f7039d = z3;
        }

        public final int a() {
            return this.f7038c;
        }

        public final boolean b() {
            return this.f7039d;
        }

        public final long c() {
            return this.f7037b;
        }

        public final int d() {
            return this.f7036a;
        }

        public final void e(long j3) {
            this.f7037b = j3;
        }
    }

    private final class e implements Choreographer.FrameCallback {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private WritableArray f7040a;

        public e() {
        }

        @Override // android.view.Choreographer.FrameCallback
        public void doFrame(long j3) {
            d dVar;
            if (!JavaTimerManager.this.f7023i.get() || JavaTimerManager.this.f7024j.get()) {
                long j4 = j3 / ((long) 1000000);
                Object obj = JavaTimerManager.this.f7020f;
                JavaTimerManager javaTimerManager = JavaTimerManager.this;
                synchronized (obj) {
                    while (!javaTimerManager.f7031q.isEmpty()) {
                        try {
                            Object objPeek = javaTimerManager.f7031q.peek();
                            j.c(objPeek);
                            if (((d) objPeek).c() >= j4 || (dVar = (d) javaTimerManager.f7031q.poll()) == null) {
                                break;
                            }
                            if (this.f7040a == null) {
                                this.f7040a = Arguments.createArray();
                            }
                            WritableArray writableArray = this.f7040a;
                            if (writableArray != null) {
                                writableArray.pushInt(dVar.d());
                            }
                            if (dVar.b()) {
                                dVar.e(((long) dVar.a()) + j4);
                                javaTimerManager.f7031q.add(dVar);
                            } else {
                                javaTimerManager.f7022h.remove(dVar.d());
                            }
                        } catch (Throwable th) {
                            throw th;
                        }
                    }
                    r rVar = r.f9288a;
                }
                WritableArray writableArray2 = this.f7040a;
                if (writableArray2 != null) {
                    JavaTimerManager.this.f7017c.callTimers(writableArray2);
                    this.f7040a = null;
                }
                JavaTimerManager.this.f7018d.k(b.a.f7052f, this);
            }
        }
    }

    public JavaTimerManager(ReactApplicationContext reactApplicationContext, A1.c cVar, com.facebook.react.modules.core.b bVar, j1.e eVar) {
        j.f(reactApplicationContext, "reactApplicationContext");
        j.f(cVar, "javaScriptTimerExecutor");
        j.f(bVar, "reactChoreographer");
        j.f(eVar, "devSupportManager");
        this.f7016b = reactApplicationContext;
        this.f7017c = cVar;
        this.f7018d = bVar;
        this.f7019e = eVar;
        this.f7020f = new Object();
        this.f7021g = new Object();
        this.f7022h = new SparseArray();
        this.f7023i = new AtomicBoolean(true);
        this.f7024j = new AtomicBoolean(false);
        this.f7025k = new e();
        this.f7026l = new c();
        final p pVar = new p() { // from class: com.facebook.react.modules.core.a
            @Override // s2.p
            public final Object b(Object obj, Object obj2) {
                return Integer.valueOf(JavaTimerManager.B((JavaTimerManager.d) obj, (JavaTimerManager.d) obj2));
            }
        };
        this.f7031q = new PriorityQueue(11, new Comparator() { // from class: A1.d
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return JavaTimerManager.C(pVar, obj, obj2);
            }
        });
        reactApplicationContext.addLifecycleEventListener(this);
        C0696c.f10181g.a(reactApplicationContext).c(this);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void A(JavaTimerManager javaTimerManager, boolean z3) {
        synchronized (javaTimerManager.f7021g) {
            try {
                if (z3) {
                    javaTimerManager.z();
                } else {
                    javaTimerManager.r();
                }
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int B(d dVar, d dVar2) {
        return u2.a.a(dVar.c() - dVar2.c());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int C(p pVar, Object obj, Object obj2) {
        return ((Number) pVar.b(obj, obj2)).intValue();
    }

    private final void r() {
        if (this.f7029o) {
            this.f7018d.n(b.a.f7053g, this.f7026l);
            this.f7029o = false;
        }
    }

    private final void s() {
        C0696c c0696cA = C0696c.f10181g.a(this.f7016b);
        if (this.f7028n && this.f7023i.get() && !c0696cA.f()) {
            this.f7018d.n(b.a.f7052f, this.f7025k);
            this.f7028n = false;
        }
    }

    private final void v() {
        if (!this.f7023i.get() || this.f7024j.get()) {
            return;
        }
        s();
    }

    private final void w() {
        synchronized (this.f7021g) {
            try {
                if (this.f7030p) {
                    z();
                }
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private final void y() {
        if (this.f7028n) {
            return;
        }
        this.f7018d.k(b.a.f7052f, this.f7025k);
        this.f7028n = true;
    }

    private final void z() {
        if (this.f7029o) {
            return;
        }
        this.f7018d.k(b.a.f7053g, this.f7026l);
        this.f7029o = true;
    }

    @Override // t1.InterfaceC0697d
    public void a(int i3) {
        if (this.f7024j.getAndSet(true)) {
            return;
        }
        y();
        w();
    }

    @Override // t1.InterfaceC0697d
    public void b(int i3) {
        if (C0696c.f10181g.a(this.f7016b).f()) {
            return;
        }
        this.f7024j.set(false);
        s();
        v();
    }

    public void createTimer(int i3, long j3, boolean z3) {
        d dVar = new d(i3, (l.b() / ((long) 1000000)) + j3, (int) j3, z3);
        synchronized (this.f7020f) {
            this.f7031q.add(dVar);
            this.f7022h.put(i3, dVar);
            r rVar = r.f9288a;
        }
    }

    public void deleteTimer(int i3) {
        synchronized (this.f7020f) {
            d dVar = (d) this.f7022h.get(i3);
            if (dVar == null) {
                return;
            }
            this.f7022h.remove(i3);
            this.f7031q.remove(dVar);
        }
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        s();
        v();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
        this.f7023i.set(true);
        s();
        v();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
        this.f7023i.set(false);
        y();
        w();
    }

    public void setSendIdleEvents(final boolean z3) {
        synchronized (this.f7021g) {
            this.f7030p = z3;
            r rVar = r.f9288a;
        }
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: A1.e
            @Override // java.lang.Runnable
            public final void run() {
                JavaTimerManager.A(this.f46b, z3);
            }
        });
    }

    public void t(int i3, int i4, double d3, boolean z3) {
        long jA = l.a();
        long j3 = (long) d3;
        if (this.f7019e.m() && Math.abs(j3 - jA) > 60000) {
            this.f7017c.emitTimeDriftWarning("Debugger and device times have drifted by more than 60s. Please correct this by running adb shell \"date `date +%m%d%H%M%Y.%S`\" on your debugger machine.");
        }
        long jMax = Math.max(0L, (j3 - jA) + ((long) i4));
        if (i4 != 0 || z3) {
            createTimer(i3, jMax, z3);
            return;
        }
        WritableArray writableArrayCreateArray = Arguments.createArray();
        writableArrayCreateArray.pushInt(i3);
        A1.c cVar = this.f7017c;
        j.c(writableArrayCreateArray);
        cVar.callTimers(writableArrayCreateArray);
    }

    public final boolean u(long j3) {
        synchronized (this.f7020f) {
            d dVar = (d) this.f7031q.peek();
            if (dVar == null) {
                return false;
            }
            if (f7015r.b(dVar, j3)) {
                return true;
            }
            Iterator it = this.f7031q.iterator();
            j.e(it, "iterator(...)");
            while (it.hasNext()) {
                d dVar2 = (d) it.next();
                a aVar = f7015r;
                j.c(dVar2);
                if (aVar.b(dVar2, j3)) {
                    return true;
                }
            }
            r rVar = r.f9288a;
            return false;
        }
    }

    public void x() {
        C0696c.f10181g.a(this.f7016b).h(this);
        this.f7016b.removeLifecycleEventListener(this);
        s();
        r();
    }
}
