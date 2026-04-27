package O1;

import android.util.LongSparseArray;
import android.view.Choreographer;
import c2.C0353a;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.modules.core.b;
import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.react.uimanager.events.RCTEventEmitter;
import com.facebook.react.uimanager.events.RCTModernEventEmitter;
import com.facebook.react.uimanager.events.ReactEventEmitter;
import d1.AbstractC0508d;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes.dex */
public class e implements EventDispatcher, LifecycleEventListener {

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private static final Comparator f2047r = new a();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ReactApplicationContext f2050d;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final c f2053g;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final d f2057k;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private volatile ReactEventEmitter f2061o;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Object f2048b = new Object();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Object f2049c = new Object();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final LongSparseArray f2051e = new LongSparseArray();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Map f2052f = AbstractC0508d.b();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final ArrayList f2054h = new ArrayList();

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final CopyOnWriteArrayList f2055i = new CopyOnWriteArrayList();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final CopyOnWriteArrayList f2056j = new CopyOnWriteArrayList();

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final AtomicInteger f2058l = new AtomicInteger();

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private O1.d[] f2059m = new O1.d[16];

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f2060n = 0;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private short f2062p = 0;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private volatile boolean f2063q = false;

    class a implements Comparator {
        a() {
        }

        @Override // java.util.Comparator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public int compare(O1.d dVar, O1.d dVar2) {
            if (dVar == null && dVar2 == null) {
                return 0;
            }
            if (dVar == null) {
                return -1;
            }
            if (dVar2 == null) {
                return 1;
            }
            long jM = dVar.m() - dVar2.m();
            if (jM == 0) {
                return 0;
            }
            return jM < 0 ? -1 : 1;
        }
    }

    class b implements Runnable {
        b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            e.this.F();
        }
    }

    private class c implements Runnable {
        @Override // java.lang.Runnable
        public void run() {
            C0353a.c(0L, "DispatchEventsRunnable");
            try {
                C0353a.f(0L, "ScheduleDispatchFrameCallback", e.this.f2058l.getAndIncrement());
                e.this.f2063q = false;
                Z0.a.c(e.this.f2061o);
                synchronized (e.this.f2049c) {
                    try {
                        if (e.this.f2060n > 0) {
                            if (e.this.f2060n > 1) {
                                Arrays.sort(e.this.f2059m, 0, e.this.f2060n, e.f2047r);
                            }
                            for (int i3 = 0; i3 < e.this.f2060n; i3++) {
                                O1.d dVar = e.this.f2059m[i3];
                                if (dVar != null) {
                                    C0353a.f(0L, dVar.k(), dVar.n());
                                    dVar.d(e.this.f2061o);
                                    dVar.e();
                                }
                            }
                            e.this.A();
                            e.this.f2051e.clear();
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                Iterator it = e.this.f2056j.iterator();
                while (it.hasNext()) {
                    ((O1.a) it.next()).a();
                }
            } finally {
                C0353a.i(0L);
            }
        }

        private c() {
        }
    }

    private class d implements Choreographer.FrameCallback {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private volatile boolean f2066a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f2067b;

        class a implements Runnable {
            a() {
            }

            @Override // java.lang.Runnable
            public void run() {
                d.this.a();
            }
        }

        private void c() {
            com.facebook.react.modules.core.b.h().k(b.a.f7052f, e.this.f2057k);
        }

        public void a() {
            if (this.f2066a) {
                return;
            }
            this.f2066a = true;
            c();
        }

        public void b() {
            if (this.f2066a) {
                return;
            }
            if (e.this.f2050d.isOnUiQueueThread()) {
                a();
            } else {
                e.this.f2050d.runOnUiQueueThread(new a());
            }
        }

        public void d() {
            this.f2067b = true;
        }

        @Override // android.view.Choreographer.FrameCallback
        public void doFrame(long j3) {
            UiThreadUtil.assertOnUiThread();
            if (this.f2067b) {
                this.f2066a = false;
            } else {
                c();
            }
            C0353a.c(0L, "ScheduleDispatchFrameCallback");
            try {
                e.this.E();
                if (!e.this.f2063q) {
                    e.this.f2063q = true;
                    C0353a.l(0L, "ScheduleDispatchFrameCallback", e.this.f2058l.get());
                    e.this.f2050d.runOnJSQueueThread(e.this.f2053g);
                }
            } finally {
                C0353a.i(0L);
            }
        }

        private d() {
            this.f2066a = false;
            this.f2067b = false;
        }
    }

    public e(ReactApplicationContext reactApplicationContext) {
        this.f2053g = new c();
        this.f2057k = new d();
        this.f2050d = reactApplicationContext;
        reactApplicationContext.addLifecycleEventListener(this);
        this.f2061o = new ReactEventEmitter(reactApplicationContext);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void A() {
        Arrays.fill(this.f2059m, 0, this.f2060n, (Object) null);
        this.f2060n = 0;
    }

    private long B(int i3, String str, short s3) {
        short sShortValue;
        Short sh = (Short) this.f2052f.get(str);
        if (sh != null) {
            sShortValue = sh.shortValue();
        } else {
            short s4 = this.f2062p;
            this.f2062p = (short) (s4 + 1);
            this.f2052f.put(str, Short.valueOf(s4));
            sShortValue = s4;
        }
        return C(i3, sShortValue, s3);
    }

    private static long C(int i3, short s3, short s4) {
        return ((((long) s3) & 65535) << 32) | ((long) i3) | ((((long) s4) & 65535) << 48);
    }

    private void D() {
        if (this.f2061o != null) {
            this.f2057k.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void E() {
        synchronized (this.f2048b) {
            synchronized (this.f2049c) {
                for (int i3 = 0; i3 < this.f2054h.size(); i3++) {
                    try {
                        O1.d dVar = (O1.d) this.f2054h.get(i3);
                        if (dVar.a()) {
                            long jB = B(dVar.o(), dVar.k(), dVar.g());
                            Integer num = (Integer) this.f2051e.get(jB);
                            O1.d dVar2 = null;
                            if (num == null) {
                                this.f2051e.put(jB, Integer.valueOf(this.f2060n));
                            } else {
                                O1.d dVar3 = this.f2059m[num.intValue()];
                                O1.d dVarB = dVar.b(dVar3);
                                if (dVarB != dVar3) {
                                    this.f2051e.put(jB, Integer.valueOf(this.f2060n));
                                    this.f2059m[num.intValue()] = null;
                                    dVar2 = dVar3;
                                    dVar = dVarB;
                                } else {
                                    dVar2 = dVar;
                                    dVar = null;
                                }
                            }
                            if (dVar != null) {
                                z(dVar);
                            }
                            if (dVar2 != null) {
                                dVar2.e();
                            }
                        } else {
                            z(dVar);
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
            this.f2054h.clear();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void F() {
        UiThreadUtil.assertOnUiThread();
        this.f2057k.d();
    }

    private void z(O1.d dVar) {
        int i3 = this.f2060n;
        O1.d[] dVarArr = this.f2059m;
        if (i3 == dVarArr.length) {
            this.f2059m = (O1.d[]) Arrays.copyOf(dVarArr, dVarArr.length * 2);
        }
        O1.d[] dVarArr2 = this.f2059m;
        int i4 = this.f2060n;
        this.f2060n = i4 + 1;
        dVarArr2[i4] = dVar;
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void a(int i3, RCTEventEmitter rCTEventEmitter) {
        this.f2061o.register(i3, rCTEventEmitter);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void b() {
        UiThreadUtil.runOnUiThread(new b());
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void c(int i3, RCTModernEventEmitter rCTModernEventEmitter) {
        this.f2061o.register(i3, rCTModernEventEmitter);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void d(g gVar) {
        this.f2055i.add(gVar);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void e(int i3) {
        this.f2061o.unregister(i3);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void f(O1.a aVar) {
        this.f2056j.remove(aVar);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void g(O1.d dVar) {
        Z0.a.b(dVar.s(), "Dispatched event hasn't been initialized");
        Iterator it = this.f2055i.iterator();
        while (it.hasNext()) {
            ((g) it.next()).a(dVar);
        }
        synchronized (this.f2048b) {
            this.f2054h.add(dVar);
            C0353a.l(0L, dVar.k(), dVar.n());
        }
        D();
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void h() {
        D();
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void i(O1.a aVar) {
        this.f2056j.add(aVar);
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        F();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
        F();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
        D();
    }
}
