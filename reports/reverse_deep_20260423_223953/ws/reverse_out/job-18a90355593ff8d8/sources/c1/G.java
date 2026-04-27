package c1;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Bundle;
import android.os.Process;
import android.view.View;
import android.view.ViewGroup;
import c1.Q;
import c2.C0353a;
import c2.C0354b;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.BridgeReactContext;
import com.facebook.react.bridge.CatalystInstance;
import com.facebook.react.bridge.CatalystInstanceImpl;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.JavaScriptExecutor;
import com.facebook.react.bridge.JavaScriptExecutorFactory;
import com.facebook.react.bridge.NativeModuleRegistry;
import com.facebook.react.bridge.NotThreadSafeBridgeIdleDebugListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactCxxErrorHandler;
import com.facebook.react.bridge.ReactInstanceManagerInspectorTarget;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.bridge.ReactNoCrashSoftException;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UIManagerProvider;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.bridge.queue.ReactQueueConfigurationSpec;
import com.facebook.react.common.LifecycleState;
import com.facebook.react.devsupport.InspectorFlags;
import com.facebook.react.devsupport.c0;
import com.facebook.react.devsupport.inspector.InspectorNetworkRequestListener;
import com.facebook.react.internal.turbomodule.core.TurboModuleManager;
import com.facebook.react.modules.appearance.AppearanceModule;
import com.facebook.react.modules.appregistry.AppRegistry;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.uimanager.C0478x;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.InterfaceC0462o0;
import com.facebook.react.uimanager.ViewManager;
import com.facebook.soloader.SoLoader;
import i1.C0570a;
import j0.C0591c;
import j1.InterfaceC0593b;
import j1.InterfaceC0594c;
import j1.e;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import k0.C0603a;
import p1.C0647a;
import p1.InterfaceC0648b;
import q1.C0655b;

/* JADX INFO: loaded from: classes.dex */
public class G {

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private static final String f5435E = "G";

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final Q.a f5436A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private List f5437B;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private volatile LifecycleState f5441b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private f f5442c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private volatile Thread f5443d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final JavaScriptExecutorFactory f5444e;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final JSBundleLoader f5446g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final String f5447h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final List f5448i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final j1.e f5449j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final boolean f5450k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final boolean f5451l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final boolean f5452m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final NotThreadSafeBridgeIdleDebugListener f5453n;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private volatile ReactContext f5455p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final Context f5456q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private A1.a f5457r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private Activity f5458s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private ReactInstanceManagerInspectorTarget f5459t;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private final ComponentCallbacks2C0335g f5463x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private final JSExceptionHandler f5464y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private final UIManagerProvider f5465z;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Set f5440a = Collections.synchronizedSet(new HashSet());

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Collection f5445f = null;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final Object f5454o = new Object();

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final Collection f5460u = Collections.synchronizedList(new ArrayList());

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private volatile boolean f5461v = false;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private volatile Boolean f5462w = Boolean.FALSE;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private boolean f5438C = true;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private volatile boolean f5439D = false;

    class a implements A1.a {
        a() {
        }

        @Override // A1.a
        public void c() {
            G.this.K();
        }
    }

    class c implements j1.g {
        c() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void c(boolean z3) {
            if (G.this.f5439D) {
                return;
            }
            if (z3) {
                G.this.f5449j.r();
            } else if (!G.this.f5449j.u() || G.this.f5438C) {
                G.this.m0();
            } else {
                G.this.f0();
            }
        }

        @Override // j1.g
        public void a(final boolean z3) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: c1.H
                @Override // java.lang.Runnable
                public final void run() {
                    this.f5477b.c(z3);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class e implements ReactInstanceManagerInspectorTarget.TargetDelegate {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private WeakReference f5471a;

        class a implements e.a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ G f5472a;

            a(G g3) {
                this.f5472a = g3;
            }

            @Override // j1.e.a
            public void a() {
                UiThreadUtil.assertOnUiThread();
                if (this.f5472a.f5459t != null) {
                    this.f5472a.f5459t.sendDebuggerResumeCommand();
                }
            }
        }

        public e(G g3) {
            this.f5471a = new WeakReference(g3);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void b() {
            G g3 = (G) this.f5471a.get();
            if (g3 != null) {
                g3.f5449j.r();
            }
        }

        @Override // com.facebook.react.bridge.ReactInstanceManagerInspectorTarget.TargetDelegate
        public Map getMetadata() {
            G g3 = (G) this.f5471a.get();
            return com.facebook.react.modules.systeminfo.a.e(g3 != null ? g3.f5456q : null);
        }

        @Override // com.facebook.react.bridge.ReactInstanceManagerInspectorTarget.TargetDelegate
        public void loadNetworkResource(String str, InspectorNetworkRequestListener inspectorNetworkRequestListener) {
            C0570a.a(str, inspectorNetworkRequestListener);
        }

        @Override // com.facebook.react.bridge.ReactInstanceManagerInspectorTarget.TargetDelegate
        public void onReload() {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: c1.I
                @Override // java.lang.Runnable
                public final void run() {
                    this.f5479b.b();
                }
            });
        }

        @Override // com.facebook.react.bridge.ReactInstanceManagerInspectorTarget.TargetDelegate
        public void onSetPausedInDebuggerMessage(String str) {
            G g3 = (G) this.f5471a.get();
            if (g3 == null) {
                return;
            }
            if (str == null) {
                g3.f5449j.d();
            } else {
                g3.f5449j.h(str, new a(g3));
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final JavaScriptExecutorFactory f5474a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final JSBundleLoader f5475b;

        public f(JavaScriptExecutorFactory javaScriptExecutorFactory, JSBundleLoader jSBundleLoader) {
            this.f5474a = (JavaScriptExecutorFactory) Z0.a.c(javaScriptExecutorFactory);
            this.f5475b = (JSBundleLoader) Z0.a.c(jSBundleLoader);
        }

        public JSBundleLoader a() {
            return this.f5475b;
        }

        public JavaScriptExecutorFactory b() {
            return this.f5474a;
        }
    }

    G(Context context, Activity activity, A1.a aVar, JavaScriptExecutorFactory javaScriptExecutorFactory, JSBundleLoader jSBundleLoader, String str, List list, boolean z3, com.facebook.react.devsupport.H h3, boolean z4, boolean z5, NotThreadSafeBridgeIdleDebugListener notThreadSafeBridgeIdleDebugListener, LifecycleState lifecycleState, JSExceptionHandler jSExceptionHandler, j1.i iVar, boolean z6, InterfaceC0593b interfaceC0593b, int i3, int i4, UIManagerProvider uIManagerProvider, Map map, Q.a aVar2, d1.k kVar, InterfaceC0594c interfaceC0594c, InterfaceC0648b interfaceC0648b, j1.h hVar) {
        Y.a.b(f5435E, "ReactInstanceManager.ctor()");
        J(context);
        C0478x.f(context);
        this.f5456q = context;
        this.f5458s = activity;
        this.f5457r = aVar;
        this.f5444e = javaScriptExecutorFactory;
        this.f5446g = jSBundleLoader;
        this.f5447h = str;
        ArrayList arrayList = new ArrayList();
        this.f5448i = arrayList;
        this.f5450k = z3;
        this.f5451l = z4;
        this.f5452m = z5;
        C0353a.c(0L, "ReactInstanceManager.initDevSupportManager");
        j1.e eVarB = h3.b(context, w(), str, z3, iVar, interfaceC0593b, i3, map, kVar, interfaceC0594c, hVar);
        this.f5449j = eVarB;
        C0353a.i(0L);
        this.f5453n = notThreadSafeBridgeIdleDebugListener;
        this.f5441b = lifecycleState;
        this.f5463x = new ComponentCallbacks2C0335g(context);
        this.f5464y = jSExceptionHandler;
        this.f5436A = aVar2;
        synchronized (arrayList) {
            try {
                C0591c.a().c(C0603a.f9413d, "RNCore: Use Split Packages");
                arrayList.add(new C0331c(this, new a(), z6, i4));
                if (z3) {
                    arrayList.add(new C0333e());
                }
                arrayList.addAll(list);
            } catch (Throwable th) {
                throw th;
            }
        }
        this.f5465z = uIManagerProvider;
        com.facebook.react.modules.core.b.i(interfaceC0648b != null ? interfaceC0648b : C0647a.b());
        if (z3) {
            eVarB.t();
        }
        o0();
    }

    private void B(InterfaceC0462o0 interfaceC0462o0, ReactContext reactContext) {
        Y.a.b("ReactNative", "ReactInstanceManager.detachRootViewFromInstance()");
        UiThreadUtil.assertOnUiThread();
        if (interfaceC0462o0.getState().compareAndSet(1, 0)) {
            int uIManagerType = interfaceC0462o0.getUIManagerType();
            if (uIManagerType != 2) {
                ((AppRegistry) reactContext.getCatalystInstance().getJSModule(AppRegistry.class)).unmountApplicationComponentAtRootTag(interfaceC0462o0.getRootViewTag());
                return;
            }
            int rootViewTag = interfaceC0462o0.getRootViewTag();
            if (rootViewTag != -1) {
                UIManager uIManagerG = H0.g(reactContext, uIManagerType);
                if (uIManagerG != null) {
                    uIManagerG.stopSurface(rootViewTag);
                } else {
                    Y.a.I("ReactNative", "Failed to stop surface, UIManager has already gone away");
                }
            } else {
                ReactSoftExceptionLogger.logSoftException(f5435E, new RuntimeException("detachRootViewFromInstance called with ReactRootView with invalid id"));
            }
            v(interfaceC0462o0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public JavaScriptExecutorFactory E() {
        return this.f5444e;
    }

    private ReactInstanceManagerInspectorTarget F() {
        if (this.f5459t == null && InspectorFlags.getFuseboxEnabled()) {
            this.f5459t = new ReactInstanceManagerInspectorTarget(new e(this));
        }
        return this.f5459t;
    }

    static void J(Context context) {
        SoLoader.m(context, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void K() {
        UiThreadUtil.assertOnUiThread();
        A1.a aVar = this.f5457r;
        if (aVar != null) {
            aVar.c();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void L(int i3, InterfaceC0462o0 interfaceC0462o0) {
        C0353a.g(0L, "pre_rootView.onAttachedToReactInstance", i3);
        interfaceC0462o0.a(101);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void M() {
        f fVar = this.f5442c;
        if (fVar != null) {
            p0(fVar);
            this.f5442c = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void N(ReactApplicationContext reactApplicationContext) {
        try {
            q0(reactApplicationContext);
        } catch (Exception e3) {
            this.f5449j.handleException(e3);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void O(f fVar) {
        ReactMarker.logMarker(ReactMarkerConstants.REACT_CONTEXT_THREAD_END);
        synchronized (this.f5462w) {
            while (this.f5462w.booleanValue()) {
                try {
                    this.f5462w.wait();
                } catch (InterruptedException unused) {
                }
            }
        }
        this.f5461v = true;
        try {
            Process.setThreadPriority(-4);
            ReactMarker.logMarker(ReactMarkerConstants.VM_INIT);
            final ReactApplicationContext reactApplicationContextX = x(fVar.b().create(), fVar.a());
            try {
                this.f5443d = null;
                ReactMarker.logMarker(ReactMarkerConstants.PRE_SETUP_REACT_CONTEXT_START);
                Runnable runnable = new Runnable() { // from class: c1.B
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f5429b.M();
                    }
                };
                reactApplicationContextX.runOnNativeModulesQueueThread(new Runnable() { // from class: c1.C
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f5430b.N(reactApplicationContextX);
                    }
                });
                UiThreadUtil.runOnUiThread(runnable);
            } catch (Exception e3) {
                this.f5449j.handleException(e3);
            }
        } catch (Exception e4) {
            this.f5461v = false;
            this.f5443d = null;
            this.f5449j.handleException(e4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void P(InterfaceC0352y[] interfaceC0352yArr, ReactApplicationContext reactApplicationContext) {
        S();
        for (InterfaceC0352y interfaceC0352y : interfaceC0352yArr) {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void Q() {
        Process.setThreadPriority(0);
        ReactMarker.logMarker(ReactMarkerConstants.CHANGE_THREAD_PRIORITY, "js_default");
    }

    private synchronized void S() {
        if (this.f5441b == LifecycleState.f6644d) {
            V(true);
        }
    }

    private synchronized void T() {
        try {
            ReactContext reactContextC = C();
            if (reactContextC != null) {
                if (this.f5441b == LifecycleState.f6644d) {
                    reactContextC.onHostPause();
                    this.f5441b = LifecycleState.f6643c;
                }
                if (this.f5441b == LifecycleState.f6643c) {
                    reactContextC.onHostDestroy(this.f5452m);
                }
            }
            this.f5441b = LifecycleState.f6642b;
        } catch (Throwable th) {
            throw th;
        }
    }

    private synchronized void U() {
        try {
            ReactContext reactContextC = C();
            if (reactContextC != null) {
                if (this.f5441b == LifecycleState.f6642b) {
                    reactContextC.onHostResume(this.f5458s);
                    reactContextC.onHostPause();
                } else if (this.f5441b == LifecycleState.f6644d) {
                    reactContextC.onHostPause();
                }
            }
            this.f5441b = LifecycleState.f6643c;
        } catch (Throwable th) {
            throw th;
        }
    }

    private synchronized void V(boolean z3) {
        try {
            ReactContext reactContextC = C();
            if (reactContextC != null && (z3 || this.f5441b == LifecycleState.f6643c || this.f5441b == LifecycleState.f6642b)) {
                reactContextC.onHostResume(this.f5458s);
            }
            this.f5441b = LifecycleState.f6644d;
        } catch (Throwable th) {
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void f0() {
        Y.a.b("ReactNative", "ReactInstanceManager.onJSBundleLoadedFromServer()");
        l0(this.f5444e, JSBundleLoader.createCachedBundleFromNetworkLoader(this.f5449j.E(), this.f5449j.j()));
    }

    private void j0(L l3, C0336h c0336h) {
        C0354b.a(0L, "processPackage").b("className", l3.getClass().getSimpleName()).c();
        boolean z3 = l3 instanceof N;
        if (z3) {
            ((N) l3).b();
        }
        c0336h.b(l3);
        if (z3) {
            ((N) l3).c();
        }
        C0354b.b(0L).c();
    }

    private NativeModuleRegistry k0(ReactApplicationContext reactApplicationContext, List list) {
        C0336h c0336h = new C0336h(reactApplicationContext);
        ReactMarker.logMarker(ReactMarkerConstants.PROCESS_PACKAGES_START);
        synchronized (this.f5448i) {
            try {
                Iterator it = list.iterator();
                while (true) {
                    if (it.hasNext()) {
                        L l3 = (L) it.next();
                        C0353a.c(0L, "createAndProcessCustomReactPackage");
                        try {
                            j0(l3, c0336h);
                            C0353a.i(0L);
                        } catch (Throwable th) {
                            C0353a.i(0L);
                            throw th;
                        }
                    }
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
        ReactMarker.logMarker(ReactMarkerConstants.PROCESS_PACKAGES_END);
        ReactMarker.logMarker(ReactMarkerConstants.BUILD_NATIVE_MODULE_REGISTRY_START);
        C0353a.c(0L, "buildNativeModuleRegistry");
        try {
            return c0336h.a();
        } finally {
            C0353a.i(0L);
            ReactMarker.logMarker(ReactMarkerConstants.BUILD_NATIVE_MODULE_REGISTRY_END);
        }
    }

    private void l0(JavaScriptExecutorFactory javaScriptExecutorFactory, JSBundleLoader jSBundleLoader) {
        Y.a.b("ReactNative", "ReactInstanceManager.recreateReactContextInBackground()");
        UiThreadUtil.assertOnUiThread();
        f fVar = new f(javaScriptExecutorFactory, jSBundleLoader);
        if (this.f5443d == null) {
            p0(fVar);
        } else {
            this.f5442c = fVar;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void m0() {
        Y.a.b(f5435E, "ReactInstanceManager.recreateReactContextInBackgroundFromBundleLoader()");
        C0591c.a().c(C0603a.f9413d, "RNCore: load from BundleLoader");
        l0(this.f5444e, this.f5446g);
    }

    private void n0() {
        Y.a.b(f5435E, "ReactInstanceManager.recreateReactContextInBackgroundInner()");
        C0591c.a().c(C0603a.f9413d, "RNCore: recreateReactContextInBackground");
        UiThreadUtil.assertOnUiThread();
        if (this.f5450k && this.f5447h != null) {
            this.f5449j.n();
            if (!C0353a.j(0L)) {
                if (this.f5446g == null) {
                    this.f5449j.r();
                    return;
                } else {
                    this.f5449j.q(new c());
                    return;
                }
            }
        }
        m0();
    }

    private void o0() {
        Method method;
        try {
            method = G.class.getMethod("I", Exception.class);
        } catch (NoSuchMethodException e3) {
            Y.a.n("ReactInstanceHolder", "Failed to set cxx error handler function", e3);
            method = null;
        }
        ReactCxxErrorHandler.setHandleErrorFunc(this, method);
    }

    private void p0(final f fVar) {
        Y.a.b("ReactNative", "ReactInstanceManager.runCreateReactContextOnNewThread()");
        UiThreadUtil.assertOnUiThread();
        Z0.a.b(!this.f5439D, "Cannot create a new React context on an invalidated ReactInstanceManager");
        ReactMarker.logMarker(ReactMarkerConstants.REACT_BRIDGE_LOADING_START);
        synchronized (this.f5440a) {
            synchronized (this.f5454o) {
                try {
                    if (this.f5455p != null) {
                        s0(this.f5455p);
                        this.f5455p = null;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        this.f5443d = new Thread(null, new Runnable() { // from class: c1.A
            @Override // java.lang.Runnable
            public final void run() {
                this.f5427b.O(fVar);
            }
        }, "create_react_context");
        ReactMarker.logMarker(ReactMarkerConstants.REACT_CONTEXT_THREAD_START);
        this.f5443d.start();
    }

    private void q0(final ReactApplicationContext reactApplicationContext) {
        Y.a.b("ReactNative", "ReactInstanceManager.setupReactContext()");
        ReactMarker.logMarker(ReactMarkerConstants.PRE_SETUP_REACT_CONTEXT_END);
        ReactMarker.logMarker(ReactMarkerConstants.SETUP_REACT_CONTEXT_START);
        C0353a.c(0L, "setupReactContext");
        synchronized (this.f5440a) {
            try {
                synchronized (this.f5454o) {
                    this.f5455p = (ReactContext) Z0.a.c(reactApplicationContext);
                }
                CatalystInstance catalystInstance = (CatalystInstance) Z0.a.c(reactApplicationContext.getCatalystInstance());
                catalystInstance.initialize();
                this.f5449j.p(reactApplicationContext);
                this.f5463x.a(catalystInstance);
                ReactMarker.logMarker(ReactMarkerConstants.ATTACH_MEASURED_ROOT_VIEWS_START);
                Iterator it = this.f5440a.iterator();
                while (it.hasNext()) {
                    t((InterfaceC0462o0) it.next());
                }
                ReactMarker.logMarker(ReactMarkerConstants.ATTACH_MEASURED_ROOT_VIEWS_END);
            } catch (Throwable th) {
                throw th;
            }
        }
        final InterfaceC0352y[] interfaceC0352yArr = (InterfaceC0352y[]) this.f5460u.toArray(new InterfaceC0352y[this.f5460u.size()]);
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: c1.D
            @Override // java.lang.Runnable
            public final void run() {
                this.f5432b.P(interfaceC0352yArr, reactApplicationContext);
            }
        });
        reactApplicationContext.runOnJSQueueThread(new Runnable() { // from class: c1.E
            @Override // java.lang.Runnable
            public final void run() {
                G.Q();
            }
        });
        reactApplicationContext.runOnNativeModulesQueueThread(new Runnable() { // from class: c1.F
            @Override // java.lang.Runnable
            public final void run() {
                Process.setThreadPriority(0);
            }
        });
        C0353a.i(0L);
        ReactMarker.logMarker(ReactMarkerConstants.SETUP_REACT_CONTEXT_END);
        ReactMarker.logMarker(ReactMarkerConstants.REACT_BRIDGE_LOADING_END);
    }

    private void s0(ReactContext reactContext) {
        Y.a.b("ReactNative", "ReactInstanceManager.tearDownReactContext()");
        UiThreadUtil.assertOnUiThread();
        if (this.f5441b == LifecycleState.f6644d) {
            reactContext.onHostPause();
        }
        synchronized (this.f5440a) {
            try {
                Iterator it = this.f5440a.iterator();
                while (it.hasNext()) {
                    B((InterfaceC0462o0) it.next(), reactContext);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        this.f5463x.d(reactContext.getCatalystInstance());
        reactContext.destroy();
        this.f5449j.z(reactContext);
    }

    private void t(final InterfaceC0462o0 interfaceC0462o0) {
        final int iAddRootView;
        Y.a.b("ReactNative", "ReactInstanceManager.attachRootViewToInstance()");
        if (interfaceC0462o0.getState().compareAndSet(0, 1)) {
            C0353a.c(0L, "attachRootViewToInstance");
            UIManager uIManagerG = H0.g(this.f5455p, interfaceC0462o0.getUIManagerType());
            if (uIManagerG == null) {
                throw new IllegalStateException("Unable to attach a rootView to ReactInstance when UIManager is not properly initialized.");
            }
            Bundle appProperties = interfaceC0462o0.getAppProperties();
            if (interfaceC0462o0.getUIManagerType() == 2) {
                iAddRootView = uIManagerG.startSurface(interfaceC0462o0.getRootViewGroup(), interfaceC0462o0.getJSModuleName(), appProperties == null ? new WritableNativeMap() : Arguments.fromBundle(appProperties), interfaceC0462o0.getWidthMeasureSpec(), interfaceC0462o0.getHeightMeasureSpec());
                interfaceC0462o0.setShouldLogContentAppeared(true);
            } else {
                iAddRootView = uIManagerG.addRootView(interfaceC0462o0.getRootViewGroup(), appProperties == null ? new WritableNativeMap() : Arguments.fromBundle(appProperties));
                interfaceC0462o0.setRootViewTag(iAddRootView);
                interfaceC0462o0.d();
            }
            C0353a.a(0L, "pre_rootView.onAttachedToReactInstance", iAddRootView);
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: c1.z
                @Override // java.lang.Runnable
                public final void run() {
                    G.L(iAddRootView, interfaceC0462o0);
                }
            });
            C0353a.i(0L);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void t0() {
        ReactContext reactContextC = C();
        if (reactContextC == null || !reactContextC.hasActiveReactInstance()) {
            ReactSoftExceptionLogger.logSoftException(f5435E, new ReactNoCrashSoftException("Cannot toggleElementInspector, CatalystInstance not available"));
        } else {
            reactContextC.emitDeviceEvent("toggleElementInspector");
        }
    }

    public static J u() {
        return new J();
    }

    private void v(InterfaceC0462o0 interfaceC0462o0) {
        UiThreadUtil.assertOnUiThread();
        interfaceC0462o0.getState().compareAndSet(1, 0);
        ViewGroup rootViewGroup = interfaceC0462o0.getRootViewGroup();
        rootViewGroup.removeAllViews();
        rootViewGroup.setId(-1);
    }

    private c0 w() {
        return new b();
    }

    private ReactApplicationContext x(JavaScriptExecutor javaScriptExecutor, JSBundleLoader jSBundleLoader) {
        UIManager uIManagerCreateUIManager;
        Q.a aVar;
        Y.a.b("ReactNative", "ReactInstanceManager.createReactContext()");
        ReactMarker.logMarker(ReactMarkerConstants.CREATE_REACT_CONTEXT_START, javaScriptExecutor.getName());
        BridgeReactContext bridgeReactContext = new BridgeReactContext(this.f5456q);
        JSExceptionHandler jSExceptionHandler = this.f5464y;
        if (jSExceptionHandler == null) {
            jSExceptionHandler = this.f5449j;
        }
        bridgeReactContext.setJSExceptionHandler(jSExceptionHandler);
        CatalystInstanceImpl.Builder inspectorTarget = new CatalystInstanceImpl.Builder().setReactQueueConfigurationSpec(ReactQueueConfigurationSpec.createDefault()).setJSExecutor(javaScriptExecutor).setRegistry(k0(bridgeReactContext, this.f5448i)).setJSBundleLoader(jSBundleLoader).setJSExceptionHandler(jSExceptionHandler).setInspectorTarget(F());
        ReactMarker.logMarker(ReactMarkerConstants.CREATE_CATALYST_INSTANCE_START);
        C0353a.c(0L, "createCatalystInstance");
        try {
            CatalystInstanceImpl catalystInstanceImplBuild = inspectorTarget.build();
            C0353a.i(0L);
            ReactMarker.logMarker(ReactMarkerConstants.CREATE_CATALYST_INSTANCE_END);
            bridgeReactContext.initializeWithInstance(catalystInstanceImplBuild);
            catalystInstanceImplBuild.getRuntimeScheduler();
            if (C0655b.t() && (aVar = this.f5436A) != null) {
                TurboModuleManager turboModuleManager = new TurboModuleManager(catalystInstanceImplBuild.getRuntimeExecutor(), aVar.c(this.f5448i).d(bridgeReactContext).a(), catalystInstanceImplBuild.getJSCallInvokerHolder(), catalystInstanceImplBuild.getNativeMethodCallInvokerHolder());
                catalystInstanceImplBuild.setTurboModuleRegistry(turboModuleManager);
                Iterator<String> it = turboModuleManager.getEagerInitModuleNames().iterator();
                while (it.hasNext()) {
                    turboModuleManager.getModule(it.next());
                }
            }
            UIManagerProvider uIManagerProvider = this.f5465z;
            if (uIManagerProvider != null && (uIManagerCreateUIManager = uIManagerProvider.createUIManager(bridgeReactContext)) != null) {
                catalystInstanceImplBuild.setFabricUIManager(uIManagerCreateUIManager);
                uIManagerCreateUIManager.initialize();
                catalystInstanceImplBuild.setFabricUIManager(uIManagerCreateUIManager);
            }
            NotThreadSafeBridgeIdleDebugListener notThreadSafeBridgeIdleDebugListener = this.f5453n;
            if (notThreadSafeBridgeIdleDebugListener != null) {
                catalystInstanceImplBuild.addBridgeIdleDebugListener(notThreadSafeBridgeIdleDebugListener);
            }
            if (C0353a.j(0L)) {
                catalystInstanceImplBuild.setGlobalVariable("__RCTProfileIsProfiling", "true");
            }
            ReactMarker.logMarker(ReactMarkerConstants.PRE_RUN_JS_BUNDLE_START);
            C0353a.c(0L, "runJSBundle");
            catalystInstanceImplBuild.runJSBundle();
            C0353a.i(0L);
            return bridgeReactContext;
        } catch (Throwable th) {
            C0353a.i(0L);
            ReactMarker.logMarker(ReactMarkerConstants.CREATE_CATALYST_INSTANCE_END);
            throw th;
        }
    }

    public void A(InterfaceC0462o0 interfaceC0462o0) {
        ReactContext reactContext;
        UiThreadUtil.assertOnUiThread();
        if (this.f5440a.remove(interfaceC0462o0) && (reactContext = this.f5455p) != null && reactContext.hasActiveReactInstance()) {
            B(interfaceC0462o0, reactContext);
        }
    }

    public ReactContext C() {
        ReactContext reactContext;
        synchronized (this.f5454o) {
            reactContext = this.f5455p;
        }
        return reactContext;
    }

    public j1.e D() {
        return this.f5449j;
    }

    public List G(ReactApplicationContext reactApplicationContext) {
        ReactMarker.logMarker(ReactMarkerConstants.CREATE_VIEW_MANAGERS_START);
        C0353a.c(0L, "createAllViewManagers");
        try {
            if (this.f5437B == null) {
                synchronized (this.f5448i) {
                    try {
                        if (this.f5437B == null) {
                            ArrayList arrayList = new ArrayList();
                            Iterator it = this.f5448i.iterator();
                            while (it.hasNext()) {
                                arrayList.addAll(((L) it.next()).f(reactApplicationContext));
                            }
                            this.f5437B = arrayList;
                            C0353a.i(0L);
                            ReactMarker.logMarker(ReactMarkerConstants.CREATE_VIEW_MANAGERS_END);
                            return arrayList;
                        }
                    } finally {
                    }
                }
            }
            List list = this.f5437B;
            C0353a.i(0L);
            ReactMarker.logMarker(ReactMarkerConstants.CREATE_VIEW_MANAGERS_END);
            return list;
        } catch (Throwable th) {
            C0353a.i(0L);
            ReactMarker.logMarker(ReactMarkerConstants.CREATE_VIEW_MANAGERS_END);
            throw th;
        }
    }

    public Collection H() {
        Collection collection;
        C0353a.c(0L, "ReactInstanceManager.getViewManagerNames");
        try {
            Collection collection2 = this.f5445f;
            if (collection2 != null) {
                return collection2;
            }
            synchronized (this.f5454o) {
                ReactApplicationContext reactApplicationContext = (ReactApplicationContext) C();
                if (reactApplicationContext != null && reactApplicationContext.hasActiveReactInstance()) {
                    synchronized (this.f5448i) {
                        try {
                            if (this.f5445f == null) {
                                HashSet hashSet = new HashSet();
                                for (L l3 : this.f5448i) {
                                    C0354b.a(0L, "ReactInstanceManager.getViewManagerName").b("Package", l3.getClass().getSimpleName()).c();
                                    if (l3 instanceof Y) {
                                        Collection collectionD = ((Y) l3).d(reactApplicationContext);
                                        if (collectionD != null) {
                                            hashSet.addAll(collectionD);
                                        }
                                    } else {
                                        Y.a.K("ReactNative", "Package %s is not a ViewManagerOnDemandReactPackage, view managers will not be loaded", l3.getClass().getSimpleName());
                                    }
                                    C0353a.i(0L);
                                }
                                this.f5445f = hashSet;
                            }
                            collection = this.f5445f;
                        } finally {
                        }
                    }
                    return collection;
                }
                Y.a.I("ReactNative", "Calling getViewManagerNames without active context");
                return Collections.emptyList();
            }
        } finally {
            C0353a.i(0L);
        }
    }

    public void I(Exception exc) {
        this.f5449j.handleException(exc);
    }

    public void W(Activity activity, int i3, int i4, Intent intent) {
        ReactContext reactContextC = C();
        if (reactContextC != null) {
            reactContextC.onActivityResult(activity, i3, i4, intent);
        }
    }

    public void X() {
        UiThreadUtil.assertOnUiThread();
        ReactContext reactContext = this.f5455p;
        if (reactContext == null) {
            Y.a.I(f5435E, "Instance detached from instance manager");
            K();
        } else {
            DeviceEventManagerModule deviceEventManagerModule = (DeviceEventManagerModule) reactContext.getNativeModule(DeviceEventManagerModule.class);
            if (deviceEventManagerModule != null) {
                deviceEventManagerModule.emitHardwareBackPressed();
            }
        }
    }

    public void Y(Context context, Configuration configuration) {
        AppearanceModule appearanceModule;
        UiThreadUtil.assertOnUiThread();
        ReactContext reactContextC = C();
        if (reactContextC == null || (appearanceModule = (AppearanceModule) reactContextC.getNativeModule(AppearanceModule.class)) == null) {
            return;
        }
        appearanceModule.onConfigurationChanged(context);
    }

    public void Z() {
        UiThreadUtil.assertOnUiThread();
        if (this.f5450k) {
            this.f5449j.A(false);
        }
        T();
        if (this.f5452m) {
            return;
        }
        this.f5458s = null;
    }

    public void a0(Activity activity) {
        if (activity == this.f5458s) {
            Z();
        }
    }

    public void b0() {
        UiThreadUtil.assertOnUiThread();
        this.f5457r = null;
        if (this.f5450k) {
            this.f5449j.A(false);
        }
        U();
    }

    public void c0(Activity activity) {
        if (this.f5451l) {
            if (this.f5458s == null) {
                Y.a.m(f5435E, "ReactInstanceManager.onHostPause called with null activity, expected:" + this.f5458s.getClass().getSimpleName());
                StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
                int length = stackTrace.length;
                for (int i3 = 0; i3 < length; i3++) {
                    Y.a.m(f5435E, stackTrace[i3].toString());
                }
            }
            Z0.a.a(this.f5458s != null);
        }
        Activity activity2 = this.f5458s;
        if (activity2 != null) {
            Z0.a.b(activity == activity2, "Pausing an activity that is not the current activity, this is incorrect! Current activity: " + this.f5458s.getClass().getSimpleName() + " Paused activity: " + activity.getClass().getSimpleName());
        }
        b0();
    }

    public void d0(Activity activity) {
        UiThreadUtil.assertOnUiThread();
        this.f5458s = activity;
        if (this.f5450k) {
            if (activity != null) {
                View decorView = activity.getWindow().getDecorView();
                if (androidx.core.view.V.E(decorView)) {
                    this.f5449j.A(true);
                } else {
                    decorView.addOnAttachStateChangeListener(new d(decorView));
                }
            } else if (!this.f5451l) {
                this.f5449j.A(true);
            }
        }
        V(false);
    }

    public void e0(Activity activity, A1.a aVar) {
        UiThreadUtil.assertOnUiThread();
        this.f5457r = aVar;
        d0(activity);
    }

    public void g0(Intent intent) {
        DeviceEventManagerModule deviceEventManagerModule;
        UiThreadUtil.assertOnUiThread();
        ReactContext reactContextC = C();
        if (reactContextC == null) {
            Y.a.I(f5435E, "Instance detached from instance manager");
            return;
        }
        String action = intent.getAction();
        Uri data = intent.getData();
        if (data != null && (("android.intent.action.VIEW".equals(action) || "android.nfc.action.NDEF_DISCOVERED".equals(action)) && (deviceEventManagerModule = (DeviceEventManagerModule) reactContextC.getNativeModule(DeviceEventManagerModule.class)) != null)) {
            deviceEventManagerModule.emitNewIntentReceived(data);
        }
        reactContextC.onNewIntent(this.f5458s, intent);
    }

    public void h0(Activity activity) {
        Activity activity2 = this.f5458s;
        if (activity2 == null || activity != activity2) {
            return;
        }
        UiThreadUtil.assertOnUiThread();
        ReactContext reactContextC = C();
        if (reactContextC != null) {
            reactContextC.onUserLeaveHint(activity);
        }
    }

    public void i0(boolean z3) {
        UiThreadUtil.assertOnUiThread();
        ReactContext reactContextC = C();
        if (reactContextC != null) {
            reactContextC.onWindowFocusChange(z3);
        }
    }

    public void r0() {
        UiThreadUtil.assertOnUiThread();
        this.f5449j.w();
    }

    public void s(InterfaceC0462o0 interfaceC0462o0) {
        UiThreadUtil.assertOnUiThread();
        synchronized (this.f5440a) {
            try {
                if (this.f5440a.add(interfaceC0462o0)) {
                    v(interfaceC0462o0);
                } else {
                    Y.a.m("ReactNative", "ReactRoot was attached multiple times");
                }
                ReactContext reactContextC = C();
                if (this.f5443d == null && reactContextC != null) {
                    t(interfaceC0462o0);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void y() {
        Y.a.b(f5435E, "ReactInstanceManager.createReactContextInBackground()");
        UiThreadUtil.assertOnUiThread();
        if (this.f5461v) {
            return;
        }
        this.f5461v = true;
        n0();
    }

    public ViewManager z(String str) {
        ViewManager viewManagerA;
        synchronized (this.f5454o) {
            ReactApplicationContext reactApplicationContext = (ReactApplicationContext) C();
            if (reactApplicationContext != null && reactApplicationContext.hasActiveReactInstance()) {
                synchronized (this.f5448i) {
                    try {
                        for (L l3 : this.f5448i) {
                            if ((l3 instanceof Y) && (viewManagerA = ((Y) l3).a(reactApplicationContext, str)) != null) {
                                return viewManagerA;
                            }
                        }
                        return null;
                    } finally {
                    }
                }
            }
            return null;
        }
    }

    class b implements c0 {
        b() {
        }

        @Override // com.facebook.react.devsupport.c0
        public View a(String str) {
            Activity activityI = i();
            if (activityI == null) {
                return null;
            }
            W w3 = new W(activityI);
            w3.setIsFabric(C0655b.f());
            w3.u(G.this, str, new Bundle());
            return w3;
        }

        @Override // com.facebook.react.devsupport.c0
        public void b(View view) {
            if (view instanceof W) {
                ((W) view).v();
            }
        }

        @Override // com.facebook.react.devsupport.c0
        public void g() {
            G.this.t0();
        }

        @Override // com.facebook.react.devsupport.c0
        public Activity i() {
            return G.this.f5458s;
        }

        @Override // com.facebook.react.devsupport.c0
        public JavaScriptExecutorFactory k() {
            return G.this.E();
        }

        @Override // com.facebook.react.devsupport.c0
        public void j(String str) {
        }
    }

    class d implements View.OnAttachStateChangeListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ View f5469b;

        d(View view) {
            this.f5469b = view;
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewAttachedToWindow(View view) {
            this.f5469b.removeOnAttachStateChangeListener(this);
            G.this.f5449j.A(true);
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewDetachedFromWindow(View view) {
        }
    }
}
