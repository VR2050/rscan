package com.facebook.react.runtime;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import c1.ComponentCallbacks2C0335g;
import c1.InterfaceC0351x;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.MemoryPressureListener;
import com.facebook.react.bridge.NativeArray;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.bridge.ReactNoCrashBridgeNotAllowedSoftException;
import com.facebook.react.bridge.ReactNoCrashSoftException;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.RuntimeExecutor;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.queue.QueueThreadExceptionHandler;
import com.facebook.react.bridge.queue.ReactQueueConfiguration;
import com.facebook.react.common.LifecycleState;
import com.facebook.react.devsupport.C0391i;
import com.facebook.react.devsupport.InspectorFlags;
import com.facebook.react.devsupport.inspector.InspectorNetworkRequestListener;
import com.facebook.react.fabric.ComponentFactory;
import com.facebook.react.fabric.FabricUIManager;
import com.facebook.react.modules.appearance.AppearanceModule;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.runtime.C0408a;
import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder;
import com.facebook.react.uimanager.UIManagerModule;
import com.facebook.react.uimanager.events.EventDispatcher;
import f1.C0527a;
import i1.C0570a;
import j1.InterfaceC0592a;
import j1.e;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import n1.InterfaceC0634a;
import o1.InterfaceC0638a;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public class ReactHostImpl implements InterfaceC0351x {

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private static final AtomicInteger f7208B = new AtomicInteger(0);

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private H1.d f7209A;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f7210a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0413f f7211b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ComponentFactory f7212c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private j1.e f7213d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Executor f7214e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Executor f7215f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final Set f7216g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final ComponentCallbacks2C0335g f7217h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final boolean f7218i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final boolean f7219j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final C0408a f7220k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private ReactInstance f7221l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final C0408a f7222m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final AtomicReference f7223n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final AtomicReference f7224o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final C0410c f7225p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final c0 f7226q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final int f7227r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private MemoryPressureListener f7228s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private A1.a f7229t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final List f7230u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final List f7231v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private ReactHostInspectorTarget f7232w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private volatile boolean f7233x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private H1.d f7234y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private H1.d f7235z;

    class a implements e.a {
        a() {
        }

        @Override // j1.e.a
        public void a() {
            UiThreadUtil.assertOnUiThread();
            if (ReactHostImpl.this.f7232w != null) {
                ReactHostImpl.this.f7232w.sendDebuggerResumeCommand();
            }
        }
    }

    class b implements InterfaceC0592a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ String f7237a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ com.facebook.react.devsupport.E f7238b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ H1.e f7239c;

        b(String str, com.facebook.react.devsupport.E e3, H1.e eVar) {
            this.f7237a = str;
            this.f7238b = e3;
            this.f7239c = eVar;
        }

        @Override // j1.InterfaceC0592a
        public void a() {
            ReactHostImpl.this.q1("loadJSBundleFromMetro()", "Creating BundleLoader");
            this.f7239c.d(JSBundleLoader.createCachedBundleFromNetworkLoader(this.f7237a, this.f7238b.j()));
        }

        @Override // j1.InterfaceC0592a
        public void b(Exception exc) {
            this.f7239c.c(exc);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final ReactInstance f7241a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final ReactContext f7242b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final boolean f7243c;

        private c(ReactInstance reactInstance, ReactContext reactContext, boolean z3) {
            this.f7241a = reactInstance;
            this.f7242b = reactContext;
            this.f7243c = z3;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    interface d {
        void a(ReactInstance reactInstance);
    }

    /* JADX INFO: Access modifiers changed from: private */
    interface e {
        ReactInstance a(H1.d dVar, String str);
    }

    public ReactHostImpl(Context context, InterfaceC0413f interfaceC0413f, ComponentFactory componentFactory, boolean z3, boolean z4) {
        this(context, interfaceC0413f, componentFactory, Executors.newSingleThreadExecutor(), H1.d.f1035j, z3, z4);
    }

    private H1.d B0() {
        p1("isMetroRunning()");
        final H1.e eVar = new H1.e();
        c().q(new j1.g() { // from class: com.facebook.react.runtime.C
            @Override // j1.g
            public final void a(boolean z3) {
                this.f7185a.g1(eVar, z3);
            }
        });
        return eVar.a();
    }

    private void B1(String str, ReactInstance reactInstance) {
        q1(str, "Stopping all React Native surfaces");
        synchronized (this.f7216g) {
            try {
                for (e0 e0Var : this.f7216g) {
                    reactInstance.D(e0Var);
                    e0Var.e();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ Object D0(String str, d dVar, H1.d dVar2) {
        ReactInstance reactInstance = (ReactInstance) dVar2.o();
        if (reactInstance == null) {
            u1(str, "Execute: reactInstance is null. Dropping work.");
            return null;
        }
        dVar.a(reactInstance);
        return null;
    }

    private void D1(ReactInstance reactInstance) {
        if (reactInstance != null) {
            if (InspectorFlags.getFuseboxEnabled()) {
                ReactHostInspectorTarget reactHostInspectorTarget = this.f7232w;
                Z0.a.b(reactHostInspectorTarget != null && reactHostInspectorTarget.isValid(), "Host inspector target destroyed before instance was unregistered");
            }
            reactInstance.unregisterFromInspector();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ Void E0(H1.d dVar) {
        if (!dVar.s()) {
            return null;
        }
        y0(dVar.n());
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public H1.d E1() {
        return F1(0, 4);
    }

    private H1.d F1(final int i3, final int i4) {
        if (this.f7235z != null) {
            q1("waitThenCallGetOrCreateReactInstanceTaskWithRetries", "React Native is reloading. Return reload task.");
            return this.f7235z;
        }
        if (this.f7209A != null) {
            if (i3 < i4) {
                q1("waitThenCallGetOrCreateReactInstanceTaskWithRetries", "React Native is tearing down.Wait for teardown to finish, before trying again (try count = " + i3 + ").");
                return this.f7209A.v(new H1.a() { // from class: com.facebook.react.runtime.u
                    @Override // H1.a
                    public final Object a(H1.d dVar) {
                        return this.f7339a.n1(i3, i4, dVar);
                    }
                }, this.f7214e);
            }
            u1("waitThenCallGetOrCreateReactInstanceTaskWithRetries", "React Native is tearing down. Not wait for teardown to finish: reached max retries.");
        }
        return t0();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ Boolean G0(String str, d dVar, H1.d dVar2) {
        ReactInstance reactInstance = (ReactInstance) dVar2.o();
        if (reactInstance == null) {
            u1(str, "Execute: reactInstance is null. Dropping work.");
            return Boolean.FALSE;
        }
        dVar.a(reactInstance);
        return Boolean.TRUE;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void H0(WeakReference weakReference, int i3) {
        ReactInstance reactInstance = (ReactInstance) weakReference.get();
        if (reactInstance != null) {
            reactInstance.r(i3);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void I0(final WeakReference weakReference, final int i3) {
        this.f7214e.execute(new Runnable() { // from class: com.facebook.react.runtime.O
            @Override // java.lang.Runnable
            public final void run() {
                ReactHostImpl.H0(weakReference, i3);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ ReactInstance J0(String str, String str2, String str3, H1.d dVar, String str4) {
        ReactInstance reactInstance = (ReactInstance) dVar.o();
        ReactInstance reactInstance2 = this.f7221l;
        String str5 = "Stage: " + str4;
        String str6 = str + " reason: " + str2;
        if (dVar.s()) {
            u1(str3, str + ": ReactInstance task faulted. " + str5 + ". " + ("Fault reason: " + dVar.n().getMessage()) + ". " + str6);
            return reactInstance2;
        }
        if (dVar.q()) {
            u1(str3, str + ": ReactInstance task cancelled. " + str5 + ". " + str6);
            return reactInstance2;
        }
        if (reactInstance == null) {
            u1(str3, str + ": ReactInstance task returned null. " + str5 + ". " + str6);
            return reactInstance2;
        }
        if (reactInstance2 != null && reactInstance != reactInstance2) {
            u1(str3, str + ": Detected two different ReactInstances. Returning old. " + str5 + ". " + str6);
        }
        return reactInstance;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d K0(String str, Exception exc, H1.d dVar) {
        return p0(str, exc);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d L0(final String str, final Exception exc) {
        if (this.f7235z == null) {
            return p0(str, exc);
        }
        q1("destroy()", "Reloading React Native. Waiting for reload to finish before destroying React Native.");
        return this.f7235z.k(new H1.a() { // from class: com.facebook.react.runtime.k
            @Override // H1.a
            public final Object a(H1.d dVar) {
                return this.f7316a.K0(str, exc, dVar);
            }
        }, this.f7214e);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void M0() {
        UiThreadUtil.assertOnUiThread();
        A1.a aVar = this.f7229t;
        if (aVar != null) {
            aVar.c();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d N0(H1.d dVar) {
        return ((Boolean) dVar.o()).booleanValue() ? o1() : H1.d.m(this.f7211b.b());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ JSBundleLoader O0() {
        return this.f7211b.b();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d P0(e eVar, String str, H1.d dVar) {
        ReactHostInspectorTarget reactHostInspectorTarget;
        q1("getOrCreateDestroyTask()", "Starting React Native destruction");
        ReactInstance reactInstanceA = eVar.a(dVar, "1: Starting destroy");
        D1(reactInstanceA);
        if (this.f7233x && (reactHostInspectorTarget = this.f7232w) != null) {
            reactHostInspectorTarget.close();
            this.f7232w = null;
        }
        if (this.f7219j) {
            q1("getOrCreateDestroyTask()", "DevSupportManager cleanup");
            this.f7213d.l();
        }
        ReactContext reactContext = (ReactContext) this.f7222m.c();
        if (reactContext == null) {
            u1("getOrCreateDestroyTask()", "ReactContext is null. Destroy reason: " + str);
        }
        q1("getOrCreateDestroyTask()", "Move ReactHost to onHostDestroy()");
        this.f7226q.b(reactContext);
        return H1.d.m(reactInstanceA);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d Q0(e eVar, H1.d dVar) {
        ReactInstance reactInstanceA = eVar.a(dVar, "2: Stopping surfaces");
        if (reactInstanceA == null) {
            u1("getOrCreateDestroyTask()", "Skipping surface shutdown: ReactInstance null");
            return dVar;
        }
        B1("getOrCreateDestroyTask()", reactInstanceA);
        synchronized (this.f7216g) {
            this.f7216g.clear();
        }
        return dVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d R0(e eVar, String str, H1.d dVar) {
        eVar.a(dVar, "3: Destroying ReactContext");
        Iterator it = this.f7231v.iterator();
        while (it.hasNext()) {
            ((InterfaceC0688a) it.next()).a();
        }
        ReactContext reactContext = (ReactContext) this.f7222m.c();
        if (reactContext == null) {
            u1("getOrCreateDestroyTask()", "ReactContext is null. Destroy reason: " + str);
        }
        q1("getOrCreateDestroyTask()", "Destroying MemoryPressureRouter");
        this.f7217h.b(this.f7210a);
        if (reactContext != null) {
            q1("getOrCreateDestroyTask()", "Resetting ReactContext ref");
            this.f7222m.e();
            q1("getOrCreateDestroyTask()", "Destroying ReactContext");
            reactContext.destroy();
        }
        y1(null);
        W1.c.d().c();
        return dVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d S0(e eVar, H1.d dVar) {
        ReactInstance reactInstanceA = eVar.a(dVar, "4: Destroying ReactInstance");
        if (reactInstanceA == null) {
            u1("getOrCreateDestroyTask()", "Skipping ReactInstance.destroy(): ReactInstance null");
        } else {
            q1("getOrCreateDestroyTask()", "Resetting ReactInstance ptr");
            this.f7221l = null;
            q1("getOrCreateDestroyTask()", "Destroying ReactInstance");
            reactInstanceA.j();
        }
        q1("getOrCreateDestroyTask()", "Resetting start task ref");
        this.f7234y = null;
        q1("getOrCreateDestroyTask()", "Resetting destroy task ref");
        this.f7209A = null;
        return dVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ Void T0(String str, H1.d dVar) {
        if (dVar.s()) {
            v1("getOrCreateDestroyTask()", "React destruction failed. ReactInstance task faulted. Fault reason: " + dVar.n().getMessage() + ". Destroy reason: " + str, dVar.n());
        }
        if (!dVar.q()) {
            return null;
        }
        u1("getOrCreateDestroyTask()", "React destruction failed. ReactInstance task cancelled. Destroy reason: " + str);
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ C0409b U0() {
        q1("getOrCreateReactContext()", "Creating BridgelessReactContext");
        return new C0409b(this.f7210a, this);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void V0() {
        ReactMarker.logMarker(ReactMarkerConstants.REACT_BRIDGELESS_LOADING_END, 1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ c W0(H1.d dVar) {
        JSBundleLoader jSBundleLoader = (JSBundleLoader) dVar.o();
        C0409b c0409bQ0 = q0();
        j1.e eVarC = c();
        c0409bQ0.setJSExceptionHandler(eVarC);
        q1("getOrCreateReactInstanceTask()", "Creating ReactInstance");
        ReactInstance reactInstance = new ReactInstance(c0409bQ0, this.f7211b, this.f7212c, eVarC, new QueueThreadExceptionHandler() { // from class: com.facebook.react.runtime.L
            @Override // com.facebook.react.bridge.queue.QueueThreadExceptionHandler
            public final void handleException(Exception exc) {
                this.f7196a.y0(exc);
            }
        }, this.f7219j, r0());
        this.f7221l = reactInstance;
        MemoryPressureListener memoryPressureListenerA0 = a0(reactInstance);
        this.f7228s = memoryPressureListenerA0;
        this.f7217h.a(memoryPressureListenerA0);
        reactInstance.t();
        q1("getOrCreateReactInstanceTask()", "Loading JS Bundle");
        reactInstance.z(jSBundleLoader);
        q1("getOrCreateReactInstanceTask()", "Calling DevSupportManagerBase.onNewReactContextCreated(reactContext)");
        eVarC.p(c0409bQ0);
        c0409bQ0.runOnJSQueueThread(new Runnable() { // from class: com.facebook.react.runtime.M
            @Override // java.lang.Runnable
            public final void run() {
                ReactHostImpl.V0();
            }
        });
        return new c(reactInstance, c0409bQ0, this.f7235z != null);
    }

    private H1.d X(String str, final d dVar, Executor executor) {
        final String str2 = "callAfterGetOrCreateReactInstance(" + str + ")";
        if (executor == null) {
            executor = H1.d.f1034i;
        }
        return s0().u(new H1.a() { // from class: com.facebook.react.runtime.i
            @Override // H1.a
            public final Object a(H1.d dVar2) {
                return this.f7312a.D0(str2, dVar, dVar2);
            }
        }, executor).h(new H1.a() { // from class: com.facebook.react.runtime.j
            @Override // H1.a
            public final Object a(H1.d dVar2) {
                return this.f7315a.E0(dVar2);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ ReactInstance X0(H1.d dVar) {
        ReactInstance reactInstance = ((c) dVar.o()).f7241a;
        ReactContext reactContext = ((c) dVar.o()).f7242b;
        boolean z3 = ((c) dVar.o()).f7243c;
        boolean z4 = this.f7226q.a() == LifecycleState.f6644d;
        if (!z3 || z4) {
            this.f7226q.e(reactContext, e0());
        } else {
            this.f7226q.d(reactContext, e0());
        }
        q1("getOrCreateReactInstanceTask()", "Executing ReactInstanceEventListeners");
        Iterator it = this.f7230u.iterator();
        while (it.hasNext()) {
            androidx.activity.result.d.a(it.next());
        }
        return reactInstance;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ ReactInstance Y0(H1.d dVar) {
        return ((c) dVar.o()).f7241a;
    }

    private H1.d Z(String str, final d dVar, Executor executor) {
        final String str2 = "callWithExistingReactInstance(" + str + ")";
        if (executor == null) {
            executor = H1.d.f1034i;
        }
        return ((H1.d) this.f7220k.a()).u(new H1.a() { // from class: com.facebook.react.runtime.l
            @Override // H1.a
            public final Object a(H1.d dVar2) {
                return this.f7319a.G0(str2, dVar, dVar2);
            }
        }, executor);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d Z0() {
        q1("getOrCreateReactInstanceTask()", "Start");
        Z0.a.b(!this.f7233x, "Cannot start a new ReactInstance on an invalidated ReactHost");
        ReactMarker.logMarker(ReactMarkerConstants.REACT_BRIDGELESS_LOADING_START, 1);
        H1.d dVarU = k0().u(new H1.a() { // from class: com.facebook.react.runtime.G
            @Override // H1.a
            public final Object a(H1.d dVar) {
                return this.f7192a.W0(dVar);
            }
        }, this.f7214e);
        dVarU.u(new H1.a() { // from class: com.facebook.react.runtime.H
            @Override // H1.a
            public final Object a(H1.d dVar) {
                return this.f7193a.X0(dVar);
            }
        }, this.f7215f);
        return dVarU.u(new H1.a() { // from class: com.facebook.react.runtime.I
            @Override // H1.a
            public final Object a(H1.d dVar) {
                return ReactHostImpl.Y0(dVar);
            }
        }, H1.d.f1034i);
    }

    private MemoryPressureListener a0(ReactInstance reactInstance) {
        final WeakReference weakReference = new WeakReference(reactInstance);
        return new MemoryPressureListener() { // from class: com.facebook.react.runtime.r
            @Override // com.facebook.react.bridge.MemoryPressureListener
            public final void handleMemoryPressure(int i3) {
                this.f7333a.I0(weakReference, i3);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d a1(e eVar, String str, H1.d dVar) {
        q1("getOrCreateReloadTask()", "Starting React Native reload");
        ReactInstance reactInstanceA = eVar.a(dVar, "1: Starting reload");
        D1(reactInstanceA);
        ReactContext reactContext = (ReactContext) this.f7222m.c();
        if (reactContext == null) {
            u1("getOrCreateReloadTask()", "ReactContext is null. Reload reason: " + str);
        }
        if (reactContext != null && this.f7226q.a() == LifecycleState.f6644d) {
            q1("getOrCreateReloadTask()", "Calling ReactContext.onHostPause()");
            reactContext.onHostPause();
        }
        return H1.d.m(reactInstanceA);
    }

    private e b0(final String str, final String str2, final String str3) {
        return new e() { // from class: com.facebook.react.runtime.v
            @Override // com.facebook.react.runtime.ReactHostImpl.e
            public final ReactInstance a(H1.d dVar, String str4) {
                return this.f7342a.J0(str, str3, str2, dVar, str4);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d b1(e eVar, H1.d dVar) {
        ReactInstance reactInstanceA = eVar.a(dVar, "2: Surface shutdown");
        if (reactInstanceA == null) {
            u1("getOrCreateReloadTask()", "Skipping surface shutdown: ReactInstance null");
            return dVar;
        }
        B1("getOrCreateReloadTask()", reactInstanceA);
        return dVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d c1(e eVar, H1.d dVar) {
        eVar.a(dVar, "3: Destroying ReactContext");
        Iterator it = this.f7231v.iterator();
        while (it.hasNext()) {
            ((InterfaceC0688a) it.next()).a();
        }
        if (this.f7228s != null) {
            q1("getOrCreateReloadTask()", "Removing memory pressure listener");
            this.f7217h.d(this.f7228s);
        }
        ReactContext reactContext = (ReactContext) this.f7222m.c();
        if (reactContext != null) {
            q1("getOrCreateReloadTask()", "Resetting ReactContext ref");
            this.f7222m.e();
            q1("getOrCreateReloadTask()", "Destroying ReactContext");
            reactContext.destroy();
        }
        if (this.f7219j && reactContext != null) {
            q1("getOrCreateReloadTask()", "Calling DevSupportManager.onReactInstanceDestroyed(reactContext)");
            this.f7213d.z(reactContext);
        }
        return dVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d d1(e eVar, H1.d dVar) {
        ReactInstance reactInstanceA = eVar.a(dVar, "4: Destroying ReactInstance");
        if (reactInstanceA == null) {
            u1("getOrCreateReloadTask()", "Skipping ReactInstance.destroy(): ReactInstance null");
        } else {
            q1("getOrCreateReloadTask()", "Resetting ReactInstance ptr");
            this.f7221l = null;
            q1("getOrCreateReloadTask()", "Destroying ReactInstance");
            reactInstanceA.j();
        }
        q1("getOrCreateReloadTask()", "Resetting start task ref");
        this.f7234y = null;
        return t0();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d e1(e eVar, H1.d dVar) {
        ReactInstance reactInstanceA = eVar.a(dVar, "5: Restarting surfaces");
        if (reactInstanceA == null) {
            u1("getOrCreateReloadTask()", "Skipping surface restart: ReactInstance null");
            return dVar;
        }
        z1("getOrCreateReloadTask()", reactInstanceA);
        return dVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d f1(String str, H1.d dVar) {
        if (dVar.s()) {
            v1("getOrCreateReloadTask()", "Error during reload. ReactInstance task faulted. Fault reason: " + dVar.n().getMessage() + ". Reload reason: " + str, dVar.n());
        }
        if (dVar.q()) {
            u1("getOrCreateReloadTask()", "Error during reload. ReactInstance task cancelled. Reload reason: " + str);
        }
        q1("getOrCreateReloadTask()", "Resetting reload task ref");
        this.f7235z = null;
        return dVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void g1(H1.e eVar, boolean z3) {
        q1("isMetroRunning()", "Async result = " + z3);
        eVar.d(Boolean.valueOf(z3));
    }

    private Map<String, String> getHostMetadata() {
        return com.facebook.react.modules.systeminfo.a.e(this.f7210a);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void h1(String str, int i3, String str2, Callback callback, ReactInstance reactInstance) {
        q1(str, "Execute");
        reactInstance.B(i3, str2);
        ((Callback) Z0.a.c(callback)).invoke(new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d i1(String str, H1.d dVar) {
        return u0(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d j1(H1.d dVar) {
        if (!dVar.s()) {
            return dVar;
        }
        Exception excN = dVar.n();
        if (this.f7219j) {
            this.f7213d.handleException(excN);
        } else {
            this.f7211b.a(excN);
        }
        return p0("Reload failed", excN);
    }

    private H1.d k0() {
        p1("getJSBundleLoader()");
        if (this.f7219j && this.f7218i) {
            return B0().v(new H1.a() { // from class: com.facebook.react.runtime.J
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7194a.N0(dVar);
                }
            }, this.f7214e);
        }
        if (C0527a.f9198b) {
            Y.a.b("ReactHost", "Packager server access is disabled in this environment");
        }
        return H1.d.c(new Callable() { // from class: com.facebook.react.runtime.K
            @Override // java.util.concurrent.Callable
            public final Object call() {
                return this.f7195a.O0();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d k1(final String str) {
        H1.d dVarT;
        if (this.f7209A != null) {
            q1("reload()", "Waiting for destroy to finish, before reloading React Native.");
            dVarT = this.f7209A.k(new H1.a() { // from class: com.facebook.react.runtime.w
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7346a.i1(str, dVar);
                }
            }, this.f7214e).t();
        } else {
            dVarT = u0(str).t();
        }
        return dVarT.k(new H1.a() { // from class: com.facebook.react.runtime.x
            @Override // H1.a
            public final Object a(H1.d dVar) {
                return this.f7348a.j1(dVar);
            }
        }, this.f7214e);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void l1(String str, e0 e0Var, ReactInstance reactInstance) {
        q1(str, "Execute");
        reactInstance.C(e0Var);
    }

    private void loadNetworkResource(String str, InspectorNetworkRequestListener inspectorNetworkRequestListener) {
        C0570a.a(str, inspectorNetworkRequestListener);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void m1(String str, e0 e0Var, ReactInstance reactInstance) {
        q1(str, "Execute");
        reactInstance.D(e0Var);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ H1.d n1(int i3, int i4, H1.d dVar) {
        return F1(i3 + 1, i4);
    }

    private H1.d o1() {
        p1("loadJSBundleFromMetro()");
        H1.e eVar = new H1.e();
        com.facebook.react.devsupport.E e3 = (com.facebook.react.devsupport.E) c();
        String strQ = e3.f0().q((String) Z0.a.c(e3.g0()));
        e3.D0(strQ, new b(strQ, e3, eVar));
        return eVar.a();
    }

    private H1.d p0(final String str, Exception exc) {
        p1("getOrCreateDestroyTask()");
        v1("getOrCreateDestroyTask()", str, exc);
        final e eVarB0 = b0("Destroy", "getOrCreateDestroyTask()", str);
        if (this.f7209A == null) {
            q1("getOrCreateDestroyTask()", "Resetting createReactInstance task ref");
            this.f7209A = ((H1.d) this.f7220k.b()).k(new H1.a() { // from class: com.facebook.react.runtime.o
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7325a.P0(eVarB0, str, dVar);
                }
            }, this.f7215f).k(new H1.a() { // from class: com.facebook.react.runtime.p
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7328a.Q0(eVarB0, dVar);
                }
            }, this.f7214e).k(new H1.a() { // from class: com.facebook.react.runtime.q
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7330a.R0(eVarB0, str, dVar);
                }
            }, this.f7215f).k(new H1.a() { // from class: com.facebook.react.runtime.s
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7335a.S0(eVarB0, dVar);
                }
            }, this.f7214e).h(new H1.a() { // from class: com.facebook.react.runtime.t
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7337a.T0(str, dVar);
                }
            });
        }
        return this.f7209A;
    }

    private void p1(String str) {
        this.f7225p.a("ReactHost{" + this.f7227r + "}." + str);
    }

    private C0409b q0() {
        return (C0409b) this.f7222m.d(new C0408a.InterfaceC0112a() { // from class: com.facebook.react.runtime.g
            @Override // com.facebook.react.runtime.C0408a.InterfaceC0112a
            public final Object get() {
                return this.f7310a.U0();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void q1(String str, String str2) {
        this.f7225p.a("ReactHost{" + this.f7227r + "}." + str + ": " + str2);
    }

    private ReactHostInspectorTarget r0() {
        if (this.f7232w == null && InspectorFlags.getFuseboxEnabled()) {
            this.f7232w = new ReactHostInspectorTarget(this);
        }
        return this.f7232w;
    }

    private void r1(boolean z3) {
        if (this.f7219j) {
            this.f7213d.A(z3);
        }
    }

    private H1.d s0() {
        return H1.d.d(new Callable() { // from class: com.facebook.react.runtime.n
            @Override // java.util.concurrent.Callable
            public final Object call() {
                return this.f7324a.E1();
            }
        }, this.f7214e).j(new C0415h());
    }

    private void s1(ReactContext reactContext) {
        this.f7226q.b(reactContext);
        y1(null);
    }

    private void setPausedInDebuggerMessage(String str) {
        if (str == null) {
            this.f7213d.d();
        } else {
            this.f7213d.h(str, new a());
        }
    }

    private H1.d t0() {
        p1("getOrCreateReactInstanceTask()");
        return (H1.d) this.f7220k.d(new C0408a.InterfaceC0112a() { // from class: com.facebook.react.runtime.F
            @Override // com.facebook.react.runtime.C0408a.InterfaceC0112a
            public final Object get() {
                return this.f7191a.Z0();
            }
        });
    }

    private H1.d u0(final String str) {
        p1("getOrCreateReloadTask()");
        u1("getOrCreateReloadTask()", str);
        final e eVarB0 = b0("Reload", "getOrCreateReloadTask()", str);
        if (this.f7235z == null) {
            q1("getOrCreateReloadTask()", "Resetting createReactInstance task ref");
            this.f7235z = ((H1.d) this.f7220k.b()).k(new H1.a() { // from class: com.facebook.react.runtime.y
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7349a.a1(eVarB0, str, dVar);
                }
            }, this.f7215f).k(new H1.a() { // from class: com.facebook.react.runtime.z
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7352a.b1(eVarB0, dVar);
                }
            }, this.f7214e).k(new H1.a() { // from class: com.facebook.react.runtime.A
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7180a.c1(eVarB0, dVar);
                }
            }, this.f7215f).k(new H1.a() { // from class: com.facebook.react.runtime.B
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7182a.d1(eVarB0, dVar);
                }
            }, this.f7214e).k(new H1.a() { // from class: com.facebook.react.runtime.D
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7187a.e1(eVarB0, dVar);
                }
            }, this.f7214e).k(new H1.a() { // from class: com.facebook.react.runtime.E
                @Override // H1.a
                public final Object a(H1.d dVar) {
                    return this.f7189a.f1(str, dVar);
                }
            }, this.f7214e);
        }
        return this.f7235z;
    }

    private void u1(String str, String str2) {
        v1(str, str2, null);
    }

    private void v1(String str, String str2, Throwable th) {
        String str3 = "raiseSoftException(" + str + ")";
        q1(str3, str2);
        ReactSoftExceptionLogger.logSoftException("ReactHost", new ReactNoCrashSoftException(str3 + ": " + str2, th));
    }

    private void y1(Activity activity) {
        this.f7223n.set(activity);
        if (activity != null) {
            this.f7224o.set(new WeakReference(activity));
        }
    }

    private void z1(String str, ReactInstance reactInstance) {
        q1(str, "Restarting previously running React Native Surfaces");
        synchronized (this.f7216g) {
            try {
                Iterator it = this.f7216g.iterator();
                while (it.hasNext()) {
                    reactInstance.C((e0) it.next());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    boolean A0() {
        return this.f7221l != null;
    }

    InterfaceC0634a A1(final e0 e0Var) {
        final String str = "startSurface(surfaceId = " + e0Var.n() + ")";
        q1(str, "Schedule");
        W(e0Var);
        return X(str, new d() { // from class: com.facebook.react.runtime.S
            @Override // com.facebook.react.runtime.ReactHostImpl.d
            public final void a(ReactInstance reactInstance) {
                this.f7260a.l1(str, e0Var, reactInstance);
            }
        }, this.f7214e);
    }

    boolean C0(String str) {
        synchronized (this.f7216g) {
            try {
                Iterator it = this.f7216g.iterator();
                while (it.hasNext()) {
                    if (((e0) it.next()).j().equals(str)) {
                        return true;
                    }
                }
                return false;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    InterfaceC0634a C1(final e0 e0Var) {
        final String str = "stopSurface(surfaceId = " + e0Var.n() + ")";
        q1(str, "Schedule");
        d0(e0Var);
        return Z(str, new d() { // from class: com.facebook.react.runtime.T
            @Override // com.facebook.react.runtime.ReactHostImpl.d
            public final void a(ReactInstance reactInstance) {
                this.f7263a.m1(str, e0Var, reactInstance);
            }
        }, this.f7214e).t();
    }

    void W(e0 e0Var) {
        p1("attachSurface(surfaceId = " + e0Var.n() + ")");
        synchronized (this.f7216g) {
            this.f7216g.add(e0Var);
        }
    }

    H1.d Y(final String str, final String str2, final NativeArray nativeArray) {
        return Z("callFunctionOnModule(\"" + str + "\", \"" + str2 + "\")", new d() { // from class: com.facebook.react.runtime.Q
            @Override // com.facebook.react.runtime.ReactHostImpl.d
            public final void a(ReactInstance reactInstance) {
                reactInstance.callFunctionOnModule(str, str2, nativeArray);
            }
        }, null);
    }

    @Override // c1.InterfaceC0351x
    public InterfaceC0638a a(Context context, String str, Bundle bundle) {
        e0 e0Var = new e0(context, str, bundle);
        f0 f0Var = new f0(context, e0Var);
        f0Var.setShouldLogContentAppeared(true);
        e0Var.d(f0Var);
        e0Var.c(this);
        return e0Var;
    }

    @Override // c1.InterfaceC0351x
    public void b(Activity activity, A1.a aVar) {
        this.f7229t = aVar;
        t1(activity);
    }

    @Override // c1.InterfaceC0351x
    public j1.e c() {
        return (j1.e) Z0.a.c(this.f7213d);
    }

    public InterfaceC0634a c0(final String str, final Exception exc) {
        return H1.d.d(new Callable() { // from class: com.facebook.react.runtime.U
            @Override // java.util.concurrent.Callable
            public final Object call() {
                return this.f7266a.L0(str, exc);
            }
        }, this.f7214e).j(new C0415h());
    }

    @Override // c1.InterfaceC0351x
    public void d(Context context) {
        AppearanceModule appearanceModule;
        ReactContext reactContextF0 = f0();
        if (reactContextF0 == null || (appearanceModule = (AppearanceModule) reactContextF0.getNativeModule(AppearanceModule.class)) == null) {
            return;
        }
        appearanceModule.onConfigurationChanged(context);
    }

    void d0(e0 e0Var) {
        p1("detachSurface(surfaceId = " + e0Var.n() + ")");
        synchronized (this.f7216g) {
            this.f7216g.remove(e0Var);
        }
    }

    @Override // c1.InterfaceC0351x
    public void e(Activity activity) {
        p1("onUserLeaveHint(activity)");
        ReactContext reactContextF0 = f0();
        if (reactContextF0 != null) {
            reactContextF0.onUserLeaveHint(activity);
        }
    }

    Activity e0() {
        return (Activity) this.f7223n.get();
    }

    @Override // c1.InterfaceC0351x
    public void f(Activity activity) {
        p1("onHostPause(activity)");
        ReactContext reactContextF0 = f0();
        Activity activityE0 = e0();
        if (activityE0 != null) {
            String simpleName = activityE0.getClass().getSimpleName();
            String simpleName2 = activity == null ? "null" : activity.getClass().getSimpleName();
            Z0.a.b(activity == activityE0, "Pausing an activity that is not the current activity, this is incorrect! Current activity: " + simpleName + " Paused activity: " + simpleName2);
        }
        r1(false);
        this.f7229t = null;
        this.f7226q.c(reactContextF0, activityE0);
    }

    public ReactContext f0() {
        return (ReactContext) this.f7222m.c();
    }

    @Override // c1.InterfaceC0351x
    public boolean g() {
        DeviceEventManagerModule deviceEventManagerModule;
        UiThreadUtil.assertOnUiThread();
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance == null || (deviceEventManagerModule = (DeviceEventManagerModule) reactInstance.m(DeviceEventManagerModule.class)) == null) {
            return false;
        }
        deviceEventManagerModule.emitHardwareBackPressed();
        return true;
    }

    A1.a g0() {
        return new A1.a() { // from class: com.facebook.react.runtime.N
            @Override // A1.a
            public final void c() {
                this.f7197b.M0();
            }
        };
    }

    @Override // c1.InterfaceC0351x
    public void h(Activity activity) {
        p1("onHostDestroy(activity)");
        if (e0() == activity) {
            r1(false);
            s1(f0());
        }
    }

    EventDispatcher h0() {
        ReactInstance reactInstance = this.f7221l;
        return reactInstance == null ? O1.b.k() : reactInstance.k();
    }

    CallInvokerHolder i0() {
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance != null) {
            return reactInstance.getJSCallInvokerHolder();
        }
        u1("getJSCallInvokerHolder()", "Tried to get JSCallInvokerHolder while instance is not ready");
        return null;
    }

    JavaScriptContextHolder j0() {
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance != null) {
            return reactInstance.l();
        }
        return null;
    }

    Activity l0() {
        WeakReference weakReference = (WeakReference) this.f7224o.get();
        if (weakReference != null) {
            return (Activity) weakReference.get();
        }
        return null;
    }

    NativeModule m0(Class cls) {
        if (cls == UIManagerModule.class) {
            ReactSoftExceptionLogger.logSoftExceptionVerbose("ReactHost", new ReactNoCrashBridgeNotAllowedSoftException("getNativeModule(UIManagerModule.class) cannot be called when the bridge is disabled"));
        }
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance != null) {
            return reactInstance.m(cls);
        }
        return null;
    }

    NativeModule n0(String str) {
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance != null) {
            return reactInstance.n(str);
        }
        return null;
    }

    Collection o0() {
        ReactInstance reactInstance = this.f7221l;
        return reactInstance != null ? reactInstance.o() : new ArrayList();
    }

    @Override // c1.InterfaceC0351x
    public void onActivityResult(Activity activity, int i3, int i4, Intent intent) {
        String str = "onActivityResult(activity = \"" + activity + "\", requestCode = \"" + i3 + "\", resultCode = \"" + i4 + "\", data = \"" + intent + "\")";
        ReactContext reactContextF0 = f0();
        if (reactContextF0 != null) {
            reactContextF0.onActivityResult(activity, i3, i4, intent);
        } else {
            u1(str, "Tried to access onActivityResult while context is not ready");
        }
    }

    @Override // c1.InterfaceC0351x
    public void onNewIntent(Intent intent) {
        DeviceEventManagerModule deviceEventManagerModule;
        String str = "onNewIntent(intent = \"" + intent + "\")";
        ReactContext reactContextF0 = f0();
        if (reactContextF0 == null) {
            u1(str, "Tried to access onNewIntent while context is not ready");
            return;
        }
        String action = intent.getAction();
        Uri data = intent.getData();
        if (data != null && (("android.intent.action.VIEW".equals(action) || "android.nfc.action.NDEF_DISCOVERED".equals(action)) && (deviceEventManagerModule = (DeviceEventManagerModule) reactContextF0.getNativeModule(DeviceEventManagerModule.class)) != null)) {
            deviceEventManagerModule.emitNewIntentReceived(data);
        }
        reactContextF0.onNewIntent(e0(), intent);
    }

    @Override // c1.InterfaceC0351x
    public void onWindowFocusChange(boolean z3) {
        String str = "onWindowFocusChange(hasFocus = \"" + z3 + "\")";
        ReactContext reactContextF0 = f0();
        if (reactContextF0 != null) {
            reactContextF0.onWindowFocusChange(z3);
        } else {
            u1(str, "Tried to access onWindowFocusChange while context is not ready");
        }
    }

    public void t1(Activity activity) {
        p1("onHostResume(activity)");
        y1(activity);
        ReactContext reactContextF0 = f0();
        r1(true);
        this.f7226q.d(reactContextF0, e0());
    }

    public ReactQueueConfiguration v0() {
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance != null) {
            return reactInstance.p();
        }
        return null;
    }

    RuntimeExecutor w0() {
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance != null) {
            return reactInstance.getBufferedRuntimeExecutor();
        }
        u1("getRuntimeExecutor()", "Tried to get runtime executor while instance is not ready");
        return null;
    }

    H1.d w1(final int i3, final String str, final Callback callback) {
        final String str2 = "registerSegment(segmentId = \"" + i3 + "\", path = \"" + str + "\")";
        q1(str2, "Schedule");
        return Z(str2, new d() { // from class: com.facebook.react.runtime.P
            @Override // com.facebook.react.runtime.ReactHostImpl.d
            public final void a(ReactInstance reactInstance) {
                this.f7200a.h1(str2, i3, str, callback, reactInstance);
            }
        }, null);
    }

    FabricUIManager x0() {
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance == null) {
            return null;
        }
        return reactInstance.q();
    }

    public InterfaceC0634a x1(final String str) {
        return H1.d.d(new Callable() { // from class: com.facebook.react.runtime.m
            @Override // java.util.concurrent.Callable
            public final Object call() {
                return this.f7322a.k1(str);
            }
        }, this.f7214e).j(new C0415h());
    }

    void y0(Exception exc) {
        String str = "handleHostException(message = \"" + exc.getMessage() + "\")";
        p1(str);
        if (this.f7219j) {
            this.f7213d.handleException(exc);
        } else {
            this.f7211b.a(exc);
        }
        c0(str, exc);
    }

    boolean z0(Class cls) {
        ReactInstance reactInstance = this.f7221l;
        if (reactInstance != null) {
            return reactInstance.s(cls);
        }
        return false;
    }

    public ReactHostImpl(Context context, InterfaceC0413f interfaceC0413f, ComponentFactory componentFactory, Executor executor, Executor executor2, boolean z3, boolean z4) {
        this(context, interfaceC0413f, componentFactory, executor, executor2, z3, z4, null);
    }

    public ReactHostImpl(Context context, InterfaceC0413f interfaceC0413f, ComponentFactory componentFactory, Executor executor, Executor executor2, boolean z3, boolean z4, com.facebook.react.devsupport.H h3) {
        this.f7216g = new HashSet();
        this.f7220k = new C0408a(H1.d.m(null));
        this.f7222m = new C0408a();
        this.f7223n = new AtomicReference();
        this.f7224o = new AtomicReference(new WeakReference(null));
        C0410c c0410c = new C0410c(C0527a.f9198b);
        this.f7225p = c0410c;
        this.f7226q = new c0(c0410c);
        this.f7227r = f7208B.getAndIncrement();
        this.f7230u = new CopyOnWriteArrayList();
        this.f7231v = new CopyOnWriteArrayList();
        this.f7233x = false;
        this.f7234y = null;
        this.f7235z = null;
        this.f7209A = null;
        this.f7210a = context;
        this.f7211b = interfaceC0413f;
        this.f7212c = componentFactory;
        this.f7214e = executor;
        this.f7215f = executor2;
        this.f7217h = new ComponentCallbacks2C0335g(context);
        this.f7218i = z3;
        this.f7219j = z4;
        this.f7213d = (h3 == null ? new C0391i() : h3).a(context.getApplicationContext(), new W(this), interfaceC0413f.e(), true, null, null, 2, null, null, null, null, z4);
    }
}
