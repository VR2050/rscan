package O1;

import O1.k;
import android.os.Handler;
import android.view.Choreographer;
import c2.C0353a;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.modules.core.b;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.react.uimanager.events.RCTEventEmitter;
import com.facebook.react.uimanager.events.RCTModernEventEmitter;
import com.facebook.react.uimanager.events.ReactEventEmitter;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import kotlin.jvm.internal.DefaultConstructorMarker;
import q1.C0655b;

/* JADX INFO: loaded from: classes.dex */
public class k implements EventDispatcher, LifecycleEventListener {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final a f2072i = new a(null);

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final Handler f2073j;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ReactEventEmitter f2074b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ReactApplicationContext f2075c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final CopyOnWriteArrayList f2076d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final CopyOnWriteArrayList f2077e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final b f2078f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f2079g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Runnable f2080h;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    final class b implements Choreographer.FrameCallback {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private volatile boolean f2081a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f2082b;

        public b() {
        }

        private final void b() {
            com.facebook.react.modules.core.b.f7042f.a().k(b.a.f7052f, k.this.f2078f);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final void e(b bVar) {
            bVar.c();
        }

        public final void c() {
            if (this.f2081a) {
                return;
            }
            this.f2081a = true;
            b();
        }

        public final void d() {
            if (this.f2081a) {
                return;
            }
            if (k.this.f2075c.isOnUiQueueThread()) {
                c();
            } else {
                k.this.f2075c.runOnUiQueueThread(new Runnable() { // from class: O1.l
                    @Override // java.lang.Runnable
                    public final void run() {
                        k.b.e(this.f2084b);
                    }
                });
            }
        }

        @Override // android.view.Choreographer.FrameCallback
        public void doFrame(long j3) {
            UiThreadUtil.assertOnUiThread();
            if (this.f2082b) {
                this.f2081a = false;
            } else {
                b();
            }
            C0353a.c(0L, "BatchEventDispatchedListeners");
            try {
                Iterator it = k.this.f2077e.iterator();
                t2.j.e(it, "iterator(...)");
                while (it.hasNext()) {
                    ((O1.a) it.next()).a();
                }
            } finally {
                C0353a.i(0L);
            }
        }

        public final void f() {
            this.f2082b = false;
        }

        public final void g() {
            this.f2082b = true;
        }
    }

    static {
        Handler uiThreadHandler = UiThreadUtil.getUiThreadHandler();
        t2.j.e(uiThreadHandler, "getUiThreadHandler(...)");
        f2073j = uiThreadHandler;
    }

    public k(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        this.f2075c = reactApplicationContext;
        this.f2076d = new CopyOnWriteArrayList();
        this.f2077e = new CopyOnWriteArrayList();
        this.f2078f = new b();
        this.f2080h = new Runnable() { // from class: O1.j
            @Override // java.lang.Runnable
            public final void run() {
                k.p(this.f2071b);
            }
        };
        reactApplicationContext.addLifecycleEventListener(this);
        this.f2074b = new ReactEventEmitter(reactApplicationContext);
    }

    private final void o() {
        UiThreadUtil.assertOnUiThread();
        if (!C0655b.r()) {
            this.f2078f.g();
        } else {
            this.f2079g = false;
            f2073j.removeCallbacks(this.f2080h);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void p(k kVar) {
        kVar.f2079g = false;
        C0353a.c(0L, "BatchEventDispatchedListeners");
        try {
            Iterator it = kVar.f2077e.iterator();
            t2.j.e(it, "iterator(...)");
            while (it.hasNext()) {
                ((O1.a) it.next()).a();
            }
        } finally {
            C0353a.i(0L);
        }
    }

    private final void q(d dVar) {
        C0353a.c(0L, "FabricEventDispatcher.dispatchSynchronous('" + dVar.k() + "')");
        try {
            UIManager uIManagerG = H0.g(this.f2075c, 2);
            if (uIManagerG instanceof p) {
                int iL = dVar.l();
                int iO = dVar.o();
                String strK = dVar.k();
                t2.j.e(strK, "getEventName(...)");
                ((p) uIManagerG).receiveEvent(iL, iO, strK, dVar.a(), dVar.j(), dVar.i(), true);
            } else {
                ReactSoftExceptionLogger.logSoftException("FabricEventDispatcher", new IllegalStateException("Fabric UIManager expected to implement SynchronousEventReceiver."));
            }
            C0353a.i(0L);
        } catch (Throwable th) {
            C0353a.i(0L);
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void r(k kVar) {
        kVar.o();
    }

    private final void s() {
        if (!C0655b.r()) {
            this.f2078f.d();
        } else {
            if (this.f2079g) {
                return;
            }
            this.f2079g = true;
            f2073j.postAtFrontOfQueue(this.f2080h);
        }
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void a(int i3, RCTEventEmitter rCTEventEmitter) {
        t2.j.f(rCTEventEmitter, "eventEmitter");
        this.f2074b.register(i3, rCTEventEmitter);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void b() {
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: O1.i
            @Override // java.lang.Runnable
            public final void run() {
                k.r(this.f2070b);
            }
        });
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void c(int i3, RCTModernEventEmitter rCTModernEventEmitter) {
        t2.j.f(rCTModernEventEmitter, "eventEmitter");
        this.f2074b.register(i3, rCTModernEventEmitter);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void d(g gVar) {
        t2.j.f(gVar, "listener");
        this.f2076d.add(gVar);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void e(int i3) {
        this.f2074b.unregister(i3);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void f(O1.a aVar) {
        t2.j.f(aVar, "listener");
        this.f2077e.remove(aVar);
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void g(d dVar) {
        t2.j.f(dVar, "event");
        Iterator it = this.f2076d.iterator();
        t2.j.e(it, "iterator(...)");
        while (it.hasNext()) {
            ((g) it.next()).a(dVar);
        }
        if (dVar.f()) {
            q(dVar);
        } else {
            dVar.d(this.f2074b);
        }
        dVar.e();
        s();
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void h() {
        s();
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void i(O1.a aVar) {
        t2.j.f(aVar, "listener");
        this.f2077e.add(aVar);
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        o();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
        o();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
        s();
        if (C0655b.r()) {
            return;
        }
        this.f2078f.f();
    }
}
