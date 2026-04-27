package com.facebook.react.runtime;

import android.content.res.AssetManager;
import android.view.ViewGroup;
import c1.C0333e;
import c2.C0353a;
import com.facebook.fbreact.specs.NativeExceptionsManagerSpec;
import com.facebook.jni.HybridData;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.bridge.JSBundleLoaderDelegate;
import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.NativeArray;
import com.facebook.react.bridge.NativeMap;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactNoCrashSoftException;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.RuntimeExecutor;
import com.facebook.react.bridge.RuntimeScheduler;
import com.facebook.react.bridge.queue.MessageQueueThread;
import com.facebook.react.bridge.queue.MessageQueueThreadSpec;
import com.facebook.react.bridge.queue.QueueThreadExceptionHandler;
import com.facebook.react.bridge.queue.ReactQueueConfiguration;
import com.facebook.react.bridge.queue.ReactQueueConfigurationImpl;
import com.facebook.react.bridge.queue.ReactQueueConfigurationSpec;
import com.facebook.react.devsupport.l0;
import com.facebook.react.fabric.ComponentFactory;
import com.facebook.react.fabric.FabricUIManager;
import com.facebook.react.fabric.FabricUIManagerBinding;
import com.facebook.react.fabric.events.EventBeatManager;
import com.facebook.react.interfaces.exceptionmanager.ReactJsExceptionHandler;
import com.facebook.react.internal.turbomodule.core.TurboModuleManager;
import com.facebook.react.modules.core.JavaTimerManager;
import com.facebook.react.turbomodule.core.CallInvokerHolderImpl;
import com.facebook.react.turbomodule.core.NativeMethodCallInvokerHolderImpl;
import com.facebook.react.uimanager.C0478x;
import com.facebook.react.uimanager.ComponentNameResolver;
import com.facebook.react.uimanager.ComponentNameResolverBinding;
import com.facebook.react.uimanager.K0;
import com.facebook.react.uimanager.U0;
import com.facebook.react.uimanager.UIConstantsProviderBinding;
import com.facebook.react.uimanager.UIManagerModule;
import com.facebook.react.uimanager.V0;
import com.facebook.react.uimanager.ViewManager;
import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.soloader.SoLoader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import p1.C0647a;
import q1.C0655b;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
final class ReactInstance {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final String f7244h = "ReactInstance";

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static volatile boolean f7245i;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final C0409b f7246a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ReactQueueConfiguration f7247b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final TurboModuleManager f7248c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final FabricUIManager f7249d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final JavaTimerManager f7250e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final b f7251f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final JavaScriptContextHolder f7252g;
    private final HybridData mHybridData;

    class a implements JSBundleLoaderDelegate {
        a() {
        }

        @Override // com.facebook.react.bridge.JSBundleLoaderDelegate
        public void loadScriptFromAssets(AssetManager assetManager, String str, boolean z3) {
            ReactInstance.this.f7246a.d(str);
            ReactInstance.this.loadJSBundleFromAssets(assetManager, str);
        }

        @Override // com.facebook.react.bridge.JSBundleLoaderDelegate
        public void loadScriptFromFile(String str, String str2, boolean z3) {
            ReactInstance.this.f7246a.d(str2);
            ReactInstance.this.loadJSBundleFromFile(str, str2);
        }

        @Override // com.facebook.react.bridge.JSBundleLoaderDelegate
        public void loadSplitBundleFromFile(String str, String str2) {
            ReactInstance.this.loadJSBundleFromFile(str, str2);
        }

        @Override // com.facebook.react.bridge.JSBundleLoaderDelegate
        public void setSourceURLs(String str, String str2) {
            ReactInstance.this.f7246a.d(str);
        }
    }

    private static class b implements V0 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final List f7254a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final C0409b f7255b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Map f7256c = new HashMap();

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private Map f7257d = null;

        public b(List list, C0409b c0409b) {
            this.f7254a = list;
            this.f7255b = c0409b;
        }

        private ViewManager d(String str) {
            ViewManager viewManagerA;
            if (this.f7256c.containsKey(str)) {
                return (ViewManager) this.f7256c.get(str);
            }
            for (c1.L l3 : this.f7254a) {
                if ((l3 instanceof c1.Y) && (viewManagerA = ((c1.Y) l3).a(this.f7255b, str)) != null) {
                    this.f7256c.put(str, viewManagerA);
                    return viewManagerA;
                }
            }
            return null;
        }

        @Override // com.facebook.react.uimanager.V0
        public synchronized ViewManager a(String str) {
            ViewManager viewManagerD = d(str);
            if (viewManagerD != null) {
                return viewManagerD;
            }
            return (ViewManager) c().get(str);
        }

        @Override // com.facebook.react.uimanager.V0
        public synchronized Collection b() {
            HashSet hashSet;
            hashSet = new HashSet();
            hashSet.addAll(e());
            hashSet.addAll(c().keySet());
            return hashSet;
        }

        public synchronized Map c() {
            try {
                Map map = this.f7257d;
                if (map != null) {
                    return map;
                }
                HashMap map2 = new HashMap();
                for (c1.L l3 : this.f7254a) {
                    if (!(l3 instanceof c1.Y)) {
                        for (ViewManager viewManager : l3.f(this.f7255b)) {
                            map2.put(viewManager.getName(), viewManager);
                        }
                    }
                }
                this.f7257d = map2;
                return map2;
            } catch (Throwable th) {
                throw th;
            }
        }

        public synchronized Collection e() {
            HashSet hashSet;
            Collection collectionD;
            hashSet = new HashSet();
            for (c1.L l3 : this.f7254a) {
                if ((l3 instanceof c1.Y) && (collectionD = ((c1.Y) l3).d(this.f7255b)) != null) {
                    hashSet.addAll(collectionD);
                }
            }
            return hashSet;
        }
    }

    private class c implements ReactJsExceptionHandler {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final QueueThreadExceptionHandler f7258a;

        c(QueueThreadExceptionHandler queueThreadExceptionHandler) {
            this.f7258a = queueThreadExceptionHandler;
        }

        @Override // com.facebook.react.interfaces.exceptionmanager.ReactJsExceptionHandler
        public void reportJsException(ReactJsExceptionHandler.ProcessedError processedError) {
            try {
                ((NativeExceptionsManagerSpec) Z0.a.c(ReactInstance.this.f7248c.getModule(NativeExceptionsManagerSpec.NAME))).reportException(l0.b(processedError));
            } catch (Exception e3) {
                this.f7258a.handleException(e3);
            }
        }
    }

    static {
        A();
    }

    ReactInstance(C0409b c0409b, InterfaceC0413f interfaceC0413f, ComponentFactory componentFactory, j1.e eVar, QueueThreadExceptionHandler queueThreadExceptionHandler, boolean z3, ReactHostInspectorTarget reactHostInspectorTarget) {
        this.f7246a = c0409b;
        C0353a.c(0L, "ReactInstance.initialize");
        ReactQueueConfigurationImpl reactQueueConfigurationImplCreate = ReactQueueConfigurationImpl.create(new ReactQueueConfigurationSpec(MessageQueueThreadSpec.newBackgroundThreadSpec("v_native"), MessageQueueThreadSpec.newBackgroundThreadSpec("v_js")), queueThreadExceptionHandler);
        this.f7247b = reactQueueConfigurationImplCreate;
        Y.a.b(f7244h, "Calling initializeMessageQueueThreads()");
        c0409b.initializeMessageQueueThreads(reactQueueConfigurationImplCreate);
        MessageQueueThread jSQueueThread = reactQueueConfigurationImplCreate.getJSQueueThread();
        MessageQueueThread nativeModulesQueueThread = reactQueueConfigurationImplCreate.getNativeModulesQueueThread();
        com.facebook.react.modules.core.b.i(C0647a.b());
        eVar.t();
        JSTimerExecutor jSTimerExecutorCreateJSTimerExecutor = createJSTimerExecutor();
        JavaTimerManager javaTimerManager = new JavaTimerManager(c0409b, jSTimerExecutorCreateJSTimerExecutor, com.facebook.react.modules.core.b.h(), eVar);
        this.f7250e = javaTimerManager;
        this.mHybridData = initHybrid(interfaceC0413f.d(), jSQueueThread, nativeModulesQueueThread, javaTimerManager, jSTimerExecutorCreateJSTimerExecutor, new c(queueThreadExceptionHandler), interfaceC0413f.getBindingsInstaller(), C0353a.j(0L), reactHostInspectorTarget);
        this.f7252g = new JavaScriptContextHolder(getJavaScriptContext());
        C0353a.c(0L, "ReactInstance.initialize#initTurboModules");
        ArrayList arrayList = new ArrayList();
        arrayList.add(new C0412e(c0409b.c(), c0409b.b()));
        if (z3) {
            arrayList.add(new C0333e());
        }
        arrayList.addAll(interfaceC0413f.f());
        c1.Q qA = interfaceC0413f.c().c(arrayList).d(c0409b).a();
        RuntimeExecutor unbufferedRuntimeExecutor = getUnbufferedRuntimeExecutor();
        this.f7248c = new TurboModuleManager(unbufferedRuntimeExecutor, qA, getJSCallInvokerHolder(), getNativeMethodCallInvokerHolder());
        C0353a.i(0L);
        C0353a.c(0L, "ReactInstance.initialize#initFabric");
        b bVar = new b(arrayList, c0409b);
        this.f7251f = bVar;
        ComponentNameResolverBinding.install(unbufferedRuntimeExecutor, new ComponentNameResolver() { // from class: com.facebook.react.runtime.Y
            @Override // com.facebook.react.uimanager.ComponentNameResolver
            public final String[] getComponentNames() {
                return this.f7271a.v();
            }
        });
        if (C0655b.q()) {
            final HashMap map = new HashMap();
            UIConstantsProviderBinding.install(unbufferedRuntimeExecutor, new UIConstantsProviderBinding.DefaultEventTypesProvider() { // from class: com.facebook.react.runtime.Z
                @Override // com.facebook.react.uimanager.UIConstantsProviderBinding.DefaultEventTypesProvider
                public final NativeMap getDefaultEventTypes() {
                    return ReactInstance.w();
                }
            }, new UIConstantsProviderBinding.ConstantsForViewManagerProvider() { // from class: com.facebook.react.runtime.a0
                @Override // com.facebook.react.uimanager.UIConstantsProviderBinding.ConstantsForViewManagerProvider
                public final NativeMap getConstantsForViewManager(String str) {
                    return this.f7281a.x(map, str);
                }
            }, new UIConstantsProviderBinding.ConstantsProvider() { // from class: com.facebook.react.runtime.b0
                @Override // com.facebook.react.uimanager.UIConstantsProviderBinding.ConstantsProvider
                public final NativeMap getConstants() {
                    return this.f7288a.y(map);
                }
            });
        }
        EventBeatManager eventBeatManager = new EventBeatManager();
        FabricUIManager fabricUIManager = new FabricUIManager(c0409b, new U0(bVar), eventBeatManager);
        this.f7249d = fabricUIManager;
        C0478x.f(c0409b);
        new FabricUIManagerBinding().i(getBufferedRuntimeExecutor(), getRuntimeScheduler(), fabricUIManager, eventBeatManager, componentFactory);
        fabricUIManager.initialize();
        C0353a.i(0L);
        C0353a.i(0L);
    }

    private static synchronized void A() {
        if (!f7245i) {
            SoLoader.t("rninstance");
            f7245i = true;
        }
    }

    private static native JSTimerExecutor createJSTimerExecutor();

    private native long getJavaScriptContext();

    private native NativeMethodCallInvokerHolderImpl getNativeMethodCallInvokerHolder();

    private native RuntimeScheduler getRuntimeScheduler();

    private native RuntimeExecutor getUnbufferedRuntimeExecutor();

    private native void handleMemoryPressureJs(int i3);

    private native HybridData initHybrid(JSRuntimeFactory jSRuntimeFactory, MessageQueueThread messageQueueThread, MessageQueueThread messageQueueThread2, JavaTimerManager javaTimerManager, JSTimerExecutor jSTimerExecutor, ReactJsExceptionHandler reactJsExceptionHandler, BindingsInstaller bindingsInstaller, boolean z3, ReactHostInspectorTarget reactHostInspectorTarget);

    private native void installGlobals(boolean z3);

    /* JADX INFO: Access modifiers changed from: private */
    public native void loadJSBundleFromAssets(AssetManager assetManager, String str);

    /* JADX INFO: Access modifiers changed from: private */
    public native void loadJSBundleFromFile(String str, String str2);

    private native void registerSegmentNative(int i3, String str);

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void u() {
        C0353a.c(0L, "initializeEagerTurboModules");
        Iterator<String> it = this.f7248c.getEagerInitModuleNames().iterator();
        while (it.hasNext()) {
            this.f7248c.getModule(it.next());
        }
        C0353a.i(0L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ String[] v() {
        Collection collectionB = this.f7251f.b();
        if (collectionB.size() >= 1) {
            return (String[]) collectionB.toArray(new String[0]);
        }
        Y.a.m(f7244h, "No ViewManager names found");
        return new String[0];
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ NativeMap w() {
        return Arguments.makeNativeMap((Map<String, Object>) K0.d());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ NativeMap x(Map map, String str) {
        ViewManager viewManagerA = this.f7251f.a(str);
        if (viewManagerA == null) {
            return null;
        }
        return (NativeMap) UIManagerModule.getConstantsForViewManager(viewManagerA, map);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ NativeMap y(Map map) {
        Map<String, Object> mapCreateConstants = UIManagerModule.createConstants(new ArrayList(this.f7251f.c().values()), null, map);
        Collection collectionE = this.f7251f.e();
        if (collectionE.size() > 0) {
            mapCreateConstants.put("ViewManagerNames", new ArrayList(collectionE));
            mapCreateConstants.put("LazyViewManagersEnabled", Boolean.TRUE);
        }
        return Arguments.makeNativeMap(mapCreateConstants);
    }

    public void B(int i3, String str) {
        registerSegmentNative(i3, str);
    }

    void C(e0 e0Var) {
        String str = f7244h;
        Y.a.b(str, "startSurface() is called with surface: " + e0Var.n());
        C0353a.c(0L, "ReactInstance.startSurface");
        ViewGroup viewGroupA = e0Var.a();
        if (viewGroupA == null) {
            throw new IllegalStateException("Starting surface without a view is not supported, use prerenderSurface instead.");
        }
        if (viewGroupA.getId() != -1) {
            ReactSoftExceptionLogger.logSoftException(str, new com.facebook.react.uimanager.P("surfaceView's is NOT equal to View.NO_ID before calling startSurface."));
            viewGroupA.setId(-1);
        }
        if (e0Var.q()) {
            this.f7249d.attachRootView(e0Var.m(), viewGroupA);
        } else {
            this.f7249d.startSurface(e0Var.m(), e0Var.h(), viewGroupA);
        }
        C0353a.i(0L);
    }

    void D(e0 e0Var) {
        Y.a.b(f7244h, "stopSurface() is called with surface: " + e0Var.n());
        this.f7249d.stopSurface(e0Var.m());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public native void callFunctionOnModule(String str, String str2, NativeArray nativeArray);

    native RuntimeExecutor getBufferedRuntimeExecutor();

    native CallInvokerHolderImpl getJSCallInvokerHolder();

    void j() {
        Y.a.b(f7244h, "ReactInstance.destroy() is called.");
        this.f7247b.destroy();
        this.f7248c.invalidate();
        this.f7249d.invalidate();
        this.f7250e.x();
        this.mHybridData.resetNative();
        this.f7252g.clear();
    }

    EventDispatcher k() {
        return this.f7249d.getEventDispatcher();
    }

    JavaScriptContextHolder l() {
        return this.f7252g;
    }

    public NativeModule m(Class cls) {
        InterfaceC0703a interfaceC0703a = (InterfaceC0703a) cls.getAnnotation(InterfaceC0703a.class);
        if (interfaceC0703a != null) {
            return n(interfaceC0703a.name());
        }
        return null;
    }

    public NativeModule n(String str) {
        NativeModule module;
        synchronized (this.f7248c) {
            module = this.f7248c.getModule(str);
        }
        return module;
    }

    public Collection o() {
        return new ArrayList(this.f7248c.getModules());
    }

    public ReactQueueConfiguration p() {
        return this.f7247b;
    }

    FabricUIManager q() {
        return this.f7249d;
    }

    public void r(int i3) {
        try {
            handleMemoryPressureJs(i3);
        } catch (NullPointerException unused) {
            ReactSoftExceptionLogger.logSoftException(f7244h, new ReactNoCrashSoftException("Native method handleMemoryPressureJs is called earlier than librninstance.so got ready."));
        }
    }

    public boolean s(Class cls) {
        InterfaceC0703a interfaceC0703a = (InterfaceC0703a) cls.getAnnotation(InterfaceC0703a.class);
        if (interfaceC0703a != null) {
            return this.f7248c.hasModule(interfaceC0703a.name());
        }
        return false;
    }

    void t() {
        this.f7247b.getNativeModulesQueueThread().runOnQueue(new Runnable() { // from class: com.facebook.react.runtime.X
            @Override // java.lang.Runnable
            public final void run() {
                this.f7270b.u();
            }
        });
    }

    native void unregisterFromInspector();

    public void z(JSBundleLoader jSBundleLoader) {
        C0353a.c(0L, "ReactInstance.loadJSBundle");
        jSBundleLoader.loadScript(new a());
        C0353a.i(0L);
    }
}
