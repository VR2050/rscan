package com.facebook.react.defaults;

import android.content.Context;
import c1.InterfaceC0351x;
import c1.K;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.defaults.DefaultTurboModuleManagerDelegate;
import com.facebook.react.fabric.ComponentFactory;
import com.facebook.react.runtime.BindingsInstaller;
import com.facebook.react.runtime.JSRuntimeFactory;
import com.facebook.react.runtime.ReactHostImpl;
import com.facebook.react.runtime.hermes.HermesInstance;
import h2.r;
import java.util.Iterator;
import java.util.List;
import s2.l;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final d f6695a = new d();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static InterfaceC0351x f6696b;

    private d() {
    }

    public static final InterfaceC0351x b(Context context, K k3, JSRuntimeFactory jSRuntimeFactory) {
        j.f(context, "context");
        j.f(k3, "reactNativeHost");
        if (k3 instanceof f) {
            return ((f) k3).A(context, jSRuntimeFactory);
        }
        throw new IllegalArgumentException("You can call getDefaultReactHost only with instances of DefaultReactNativeHost");
    }

    public static final InterfaceC0351x c(Context context, List list, String str, String str2, String str3, JSRuntimeFactory jSRuntimeFactory, boolean z3, List list2) {
        j.f(context, "context");
        j.f(list, "packageList");
        j.f(str, "jsMainModulePath");
        j.f(str2, "jsBundleAssetPath");
        j.f(list2, "cxxReactPackageProviders");
        return d(context, list, str, str2, str3, jSRuntimeFactory, z3, list2, new l() { // from class: com.facebook.react.defaults.c
            @Override // s2.l
            public final Object d(Object obj) {
                return d.g((Exception) obj);
            }
        }, null);
    }

    public static final InterfaceC0351x d(Context context, List list, String str, String str2, String str3, JSRuntimeFactory jSRuntimeFactory, boolean z3, List list2, l lVar, BindingsInstaller bindingsInstaller) {
        JSBundleLoader jSBundleLoaderCreateAssetLoader;
        j.f(context, "context");
        j.f(list, "packageList");
        j.f(str, "jsMainModulePath");
        j.f(str2, "jsBundleAssetPath");
        j.f(list2, "cxxReactPackageProviders");
        j.f(lVar, "exceptionHandler");
        if (f6696b == null) {
            if (str3 != null) {
                jSBundleLoaderCreateAssetLoader = z2.g.u(str3, "assets://", false, 2, null) ? JSBundleLoader.createAssetLoader(context, str3, true) : JSBundleLoader.createFileLoader(str3);
            } else {
                jSBundleLoaderCreateAssetLoader = JSBundleLoader.createAssetLoader(context, "assets://" + str2, true);
            }
            JSBundleLoader jSBundleLoader = jSBundleLoaderCreateAssetLoader;
            DefaultTurboModuleManagerDelegate.a aVar = new DefaultTurboModuleManagerDelegate.a();
            Iterator it = list2.iterator();
            while (it.hasNext()) {
                aVar.f((l) it.next());
            }
            j.c(jSBundleLoader);
            DefaultReactHostDelegate defaultReactHostDelegate = new DefaultReactHostDelegate(str, jSBundleLoader, list, jSRuntimeFactory == null ? new HermesInstance() : jSRuntimeFactory, bindingsInstaller, lVar, aVar);
            ComponentFactory componentFactory = new ComponentFactory();
            DefaultComponentsRegistry.register(componentFactory);
            f6696b = new ReactHostImpl(context, defaultReactHostDelegate, componentFactory, true, z3);
        }
        InterfaceC0351x interfaceC0351x = f6696b;
        j.d(interfaceC0351x, "null cannot be cast to non-null type com.facebook.react.ReactHost");
        return interfaceC0351x;
    }

    public static /* synthetic */ InterfaceC0351x e(Context context, K k3, JSRuntimeFactory jSRuntimeFactory, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            jSRuntimeFactory = null;
        }
        return b(context, k3, jSRuntimeFactory);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final r g(Exception exc) throws Exception {
        j.f(exc, "it");
        throw exc;
    }
}
