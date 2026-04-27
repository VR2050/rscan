package com.facebook.react.defaults;

import c1.Q;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.runtime.BindingsInstaller;
import com.facebook.react.runtime.InterfaceC0413f;
import com.facebook.react.runtime.JSRuntimeFactory;
import java.util.List;
import s2.l;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class DefaultReactHostDelegate implements InterfaceC0413f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f6679a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final JSBundleLoader f6680b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final List f6681c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final JSRuntimeFactory f6682d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final BindingsInstaller f6683e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final l f6684f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final Q.a f6685g;

    public DefaultReactHostDelegate(String str, JSBundleLoader jSBundleLoader, List list, JSRuntimeFactory jSRuntimeFactory, BindingsInstaller bindingsInstaller, l lVar, Q.a aVar) {
        j.f(str, "jsMainModulePath");
        j.f(jSBundleLoader, "jsBundleLoader");
        j.f(list, "reactPackages");
        j.f(jSRuntimeFactory, "jsRuntimeFactory");
        j.f(lVar, "exceptionHandler");
        j.f(aVar, "turboModuleManagerDelegateBuilder");
        this.f6679a = str;
        this.f6680b = jSBundleLoader;
        this.f6681c = list;
        this.f6682d = jSRuntimeFactory;
        this.f6683e = bindingsInstaller;
        this.f6684f = lVar;
        this.f6685g = aVar;
    }

    @Override // com.facebook.react.runtime.InterfaceC0413f
    public void a(Exception exc) {
        j.f(exc, "error");
        this.f6684f.d(exc);
    }

    @Override // com.facebook.react.runtime.InterfaceC0413f
    public JSBundleLoader b() {
        return this.f6680b;
    }

    @Override // com.facebook.react.runtime.InterfaceC0413f
    public Q.a c() {
        return this.f6685g;
    }

    @Override // com.facebook.react.runtime.InterfaceC0413f
    public JSRuntimeFactory d() {
        return this.f6682d;
    }

    @Override // com.facebook.react.runtime.InterfaceC0413f
    public String e() {
        return this.f6679a;
    }

    @Override // com.facebook.react.runtime.InterfaceC0413f
    public List f() {
        return this.f6681c;
    }

    @Override // com.facebook.react.runtime.InterfaceC0413f
    public BindingsInstaller getBindingsInstaller() {
        return this.f6683e;
    }
}
