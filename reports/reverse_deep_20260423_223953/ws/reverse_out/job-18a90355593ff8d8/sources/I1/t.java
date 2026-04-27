package I1;

import I0.C0195u;
import c1.AbstractC0329a;
import c1.Y;
import com.facebook.fbreact.specs.NativeAnimatedModuleSpec;
import com.facebook.fbreact.specs.NativeBlobModuleSpec;
import com.facebook.fbreact.specs.NativeDialogManagerAndroidSpec;
import com.facebook.fbreact.specs.NativeFileReaderModuleSpec;
import com.facebook.fbreact.specs.NativeNetworkingAndroidSpec;
import com.facebook.react.animated.NativeAnimatedModule;
import com.facebook.react.bridge.ModuleSpec;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.modules.accessibilityinfo.AccessibilityInfoModule;
import com.facebook.react.modules.appearance.AppearanceModule;
import com.facebook.react.modules.appstate.AppStateModule;
import com.facebook.react.modules.blob.BlobModule;
import com.facebook.react.modules.blob.FileReaderModule;
import com.facebook.react.modules.camera.ImageStoreManager;
import com.facebook.react.modules.clipboard.ClipboardModule;
import com.facebook.react.modules.devloading.DevLoadingModule;
import com.facebook.react.modules.devtoolsruntimesettings.ReactDevToolsRuntimeSettingsModule;
import com.facebook.react.modules.dialog.DialogModule;
import com.facebook.react.modules.fresco.FrescoModule;
import com.facebook.react.modules.i18nmanager.I18nManagerModule;
import com.facebook.react.modules.image.ImageLoaderModule;
import com.facebook.react.modules.intent.IntentModule;
import com.facebook.react.modules.network.NetworkingModule;
import com.facebook.react.modules.permissions.PermissionsModule;
import com.facebook.react.modules.reactdevtoolssettings.ReactDevToolsSettingsManagerModule;
import com.facebook.react.modules.share.ShareModule;
import com.facebook.react.modules.sound.SoundManagerModule;
import com.facebook.react.modules.statusbar.StatusBarModule;
import com.facebook.react.modules.toast.ToastModule;
import com.facebook.react.modules.vibration.VibrationModule;
import com.facebook.react.modules.websocket.WebSocketModule;
import com.facebook.react.uimanager.ViewManager;
import com.facebook.react.views.drawer.ReactDrawerLayoutManager;
import com.facebook.react.views.image.ReactImageManager;
import com.facebook.react.views.modal.ReactModalHostManager;
import com.facebook.react.views.progressbar.ReactProgressBarViewManager;
import com.facebook.react.views.safeareaview.ReactSafeAreaViewManager;
import com.facebook.react.views.scroll.ReactHorizontalScrollContainerViewManager;
import com.facebook.react.views.scroll.ReactHorizontalScrollViewManager;
import com.facebook.react.views.scroll.ReactScrollViewManager;
import com.facebook.react.views.swiperefresh.SwipeRefreshLayoutManager;
import com.facebook.react.views.switchview.ReactSwitchManager;
import com.facebook.react.views.text.ReactRawTextManager;
import com.facebook.react.views.text.ReactTextViewManager;
import com.facebook.react.views.text.ReactVirtualTextViewManager;
import com.facebook.react.views.text.frescosupport.FrescoBasedReactTextInlineImageViewManager;
import com.facebook.react.views.textinput.ReactTextInputManager;
import com.facebook.react.views.unimplementedview.ReactUnimplementedViewManager;
import com.facebook.react.views.view.ReactViewManager;
import d1.C0505a;
import h2.C0563i;
import i2.AbstractC0586n;
import i2.D;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.inject.Provider;
import u1.InterfaceC0703a;
import v1.InterfaceC0708a;

/* JADX INFO: loaded from: classes.dex */
public final class t extends AbstractC0329a implements Y {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Map f1422a = D.h(h2.n.a(ReactDrawerLayoutManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.k
        @Override // javax.inject.Provider
        public final Object get() {
            return t.E();
        }
    })), h2.n.a(ReactHorizontalScrollViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.s
        @Override // javax.inject.Provider
        public final Object get() {
            return t.F();
        }
    })), h2.n.a(ReactHorizontalScrollContainerViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.c
        @Override // javax.inject.Provider
        public final Object get() {
            return t.N();
        }
    })), h2.n.a(ReactProgressBarViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.d
        @Override // javax.inject.Provider
        public final Object get() {
            return t.O();
        }
    })), h2.n.a(ReactSafeAreaViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.e
        @Override // javax.inject.Provider
        public final Object get() {
            return t.P();
        }
    })), h2.n.a(ReactScrollViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.f
        @Override // javax.inject.Provider
        public final Object get() {
            return t.Q();
        }
    })), h2.n.a(ReactSwitchManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.g
        @Override // javax.inject.Provider
        public final Object get() {
            return t.R();
        }
    })), h2.n.a(SwipeRefreshLayoutManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.h
        @Override // javax.inject.Provider
        public final Object get() {
            return t.S();
        }
    })), h2.n.a(FrescoBasedReactTextInlineImageViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.i
        @Override // javax.inject.Provider
        public final Object get() {
            return t.T();
        }
    })), h2.n.a(ReactImageManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.j
        @Override // javax.inject.Provider
        public final Object get() {
            return t.U();
        }
    })), h2.n.a(ReactModalHostManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.l
        @Override // javax.inject.Provider
        public final Object get() {
            return t.G();
        }
    })), h2.n.a(ReactRawTextManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.m
        @Override // javax.inject.Provider
        public final Object get() {
            return t.H();
        }
    })), h2.n.a(ReactTextInputManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.n
        @Override // javax.inject.Provider
        public final Object get() {
            return t.I();
        }
    })), h2.n.a(ReactTextViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.o
        @Override // javax.inject.Provider
        public final Object get() {
            return t.J();
        }
    })), h2.n.a(ReactViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.p
        @Override // javax.inject.Provider
        public final Object get() {
            return t.K();
        }
    })), h2.n.a(ReactVirtualTextViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.q
        @Override // javax.inject.Provider
        public final Object get() {
            return t.L();
        }
    })), h2.n.a(ReactUnimplementedViewManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: I1.r
        @Override // javax.inject.Provider
        public final Object get() {
            return t.M();
        }
    })));

    public t(a aVar) {
    }

    private final InterfaceC0708a C() {
        Class[] clsArr = {AccessibilityInfoModule.class, AppearanceModule.class, AppStateModule.class, BlobModule.class, DevLoadingModule.class, FileReaderModule.class, ClipboardModule.class, DialogModule.class, FrescoModule.class, I18nManagerModule.class, ImageLoaderModule.class, ImageStoreManager.class, IntentModule.class, NativeAnimatedModule.class, NetworkingModule.class, PermissionsModule.class, ReactDevToolsSettingsManagerModule.class, ReactDevToolsRuntimeSettingsModule.class, ShareModule.class, StatusBarModule.class, SoundManagerModule.class, ToastModule.class, VibrationModule.class, WebSocketModule.class};
        ArrayList<Class> arrayList = new ArrayList();
        for (int i3 = 0; i3 < 24; i3++) {
            Class cls = clsArr[i3];
            if (cls.isAnnotationPresent(InterfaceC0703a.class)) {
                arrayList.add(cls);
            }
        }
        final LinkedHashMap linkedHashMap = new LinkedHashMap(w2.d.c(D.c(AbstractC0586n.o(arrayList, 10)), 16));
        for (Class cls2 : arrayList) {
            Annotation annotation = cls2.getAnnotation(InterfaceC0703a.class);
            if (annotation == null) {
                throw new IllegalStateException("Required value was null.");
            }
            InterfaceC0703a interfaceC0703a = (InterfaceC0703a) annotation;
            String strName = interfaceC0703a.name();
            String strName2 = interfaceC0703a.name();
            String name = cls2.getName();
            t2.j.e(name, "getName(...)");
            C0563i c0563iA = h2.n.a(strName, new ReactModuleInfo(strName2, name, interfaceC0703a.canOverrideExistingModule(), interfaceC0703a.needsEagerInit(), interfaceC0703a.isCxxModule(), ReactModuleInfo.f6999g.a(cls2)));
            linkedHashMap.put(c0563iA.c(), c0563iA.d());
        }
        return new InterfaceC0708a() { // from class: I1.b
            @Override // v1.InterfaceC0708a
            public final Map a() {
                return t.D(linkedHashMap);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule E() {
        return new ReactDrawerLayoutManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule F() {
        return new ReactHorizontalScrollViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule G() {
        return new ReactModalHostManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule H() {
        return new ReactRawTextManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule I() {
        return new ReactTextInputManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule J() {
        return new ReactTextViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule K() {
        return new ReactViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule L() {
        return new ReactVirtualTextViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule M() {
        return new ReactUnimplementedViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule N() {
        return new ReactHorizontalScrollContainerViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule O() {
        return new ReactProgressBarViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule P() {
        return new ReactSafeAreaViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule Q() {
        return new ReactScrollViewManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule R() {
        return new ReactSwitchManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule S() {
        return new SwipeRefreshLayoutManager();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public static final NativeModule T() {
        return new FrescoBasedReactTextInlineImageViewManager(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NativeModule U() {
        return new ReactImageManager(null, null, null, 7, null);
    }

    @Override // c1.Y
    public ViewManager a(ReactApplicationContext reactApplicationContext, String str) {
        Provider provider;
        t2.j.f(reactApplicationContext, "reactContext");
        t2.j.f(str, "viewManagerName");
        ModuleSpec moduleSpec = (ModuleSpec) this.f1422a.get(str);
        NativeModule nativeModule = (moduleSpec == null || (provider = moduleSpec.getProvider()) == null) ? null : (NativeModule) provider.get();
        if (nativeModule instanceof ViewManager) {
            return (ViewManager) nativeModule;
        }
        return null;
    }

    @Override // c1.Y
    public Collection d(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        return this.f1422a.keySet();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // c1.AbstractC0329a, c1.L
    public List f(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        return AbstractC0586n.i(new ReactDrawerLayoutManager(), new ReactHorizontalScrollViewManager(), new ReactHorizontalScrollContainerViewManager(), new ReactProgressBarViewManager(), new ReactScrollViewManager(), new ReactSwitchManager(), new ReactSafeAreaViewManager(), new SwipeRefreshLayoutManager(), new FrescoBasedReactTextInlineImageViewManager(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0), new ReactImageManager(null, null, null, 7, null), new ReactModalHostManager(), new ReactRawTextManager(), new ReactTextInputManager(), new ReactTextViewManager(), new ReactViewManager(), new ReactVirtualTextViewManager(), new ReactUnimplementedViewManager());
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @Override // c1.AbstractC0329a
    public NativeModule g(String str, ReactApplicationContext reactApplicationContext) {
        NativeModule appearanceModule;
        t2.j.f(str, "name");
        t2.j.f(reactApplicationContext, "reactContext");
        switch (str.hashCode()) {
            case -2115067288:
                if (str.equals("ToastAndroid")) {
                    return new ToastModule(reactApplicationContext);
                }
                return null;
            case -1962922905:
                if (str.equals("ImageStoreManager")) {
                    return new ImageStoreManager(reactApplicationContext);
                }
                return null;
            case -1850625090:
                if (str.equals("SoundManager")) {
                    return new SoundManagerModule(reactApplicationContext);
                }
                return null;
            case -1654566518:
                if (str.equals(NativeDialogManagerAndroidSpec.NAME)) {
                    return new DialogModule(reactApplicationContext);
                }
                return null;
            case -1344126773:
                if (str.equals(NativeFileReaderModuleSpec.NAME)) {
                    return new FileReaderModule(reactApplicationContext);
                }
                return null;
            case -1067020766:
                if (str.equals("ReactDevToolsRuntimeSettingsModule")) {
                    return new ReactDevToolsRuntimeSettingsModule(reactApplicationContext);
                }
                return null;
            case -1062061717:
                if (str.equals("PermissionsAndroid")) {
                    return new PermissionsModule(reactApplicationContext);
                }
                return null;
            case -657277650:
                if (str.equals("ImageLoader")) {
                    return new ImageLoaderModule(reactApplicationContext);
                }
                return null;
            case -585704955:
                if (str.equals("ReactDevToolsSettingsManager")) {
                    return new ReactDevToolsSettingsManagerModule(reactApplicationContext);
                }
                return null;
            case -570370161:
                if (str.equals("I18nManager")) {
                    return new I18nManagerModule(reactApplicationContext);
                }
                return null;
            case -504784764:
                if (!str.equals("Appearance")) {
                    return null;
                }
                appearanceModule = new AppearanceModule(reactApplicationContext, null, 2, null);
                break;
                break;
            case -457866500:
                if (str.equals("AccessibilityInfo")) {
                    return new AccessibilityInfoModule(reactApplicationContext);
                }
                return null;
            case -382654004:
                if (str.equals("StatusBarManager")) {
                    return new StatusBarModule(reactApplicationContext);
                }
                return null;
            case -254310125:
                if (str.equals("WebSocketModule")) {
                    return new WebSocketModule(reactApplicationContext);
                }
                return null;
            case -99249460:
                if (str.equals("DevLoadingView")) {
                    return new DevLoadingModule(reactApplicationContext);
                }
                return null;
            case 163245714:
                if (!str.equals(FrescoModule.NAME)) {
                    return null;
                }
                appearanceModule = new FrescoModule(reactApplicationContext, true, (C0195u) null);
                break;
                break;
            case 403570038:
                if (str.equals("Clipboard")) {
                    return new ClipboardModule(reactApplicationContext);
                }
                return null;
            case 563961875:
                if (str.equals("IntentAndroid")) {
                    return new IntentModule(reactApplicationContext);
                }
                return null;
            case 1221389072:
                if (str.equals("AppState")) {
                    return new AppStateModule(reactApplicationContext);
                }
                return null;
            case 1515242260:
                if (str.equals(NativeNetworkingAndroidSpec.NAME)) {
                    return new NetworkingModule(reactApplicationContext);
                }
                return null;
            case 1547941001:
                if (str.equals(NativeBlobModuleSpec.NAME)) {
                    return new BlobModule(reactApplicationContext);
                }
                return null;
            case 1555425035:
                if (str.equals("ShareModule")) {
                    return new ShareModule(reactApplicationContext);
                }
                return null;
            case 1721274886:
                if (str.equals(NativeAnimatedModuleSpec.NAME)) {
                    return new NativeAnimatedModule(reactApplicationContext);
                }
                return null;
            case 1922110066:
                if (str.equals("Vibration")) {
                    return new VibrationModule(reactApplicationContext);
                }
                return null;
            default:
                return null;
        }
        return appearanceModule;
    }

    @Override // c1.AbstractC0329a
    public InterfaceC0708a i() {
        if (!C0505a.a()) {
            return C();
        }
        try {
            Class clsB = C0505a.b("com.facebook.react.shell.MainReactPackage$$ReactModuleInfoProvider");
            Object objNewInstance = clsB != null ? clsB.newInstance() : null;
            InterfaceC0708a interfaceC0708a = objNewInstance instanceof InterfaceC0708a ? (InterfaceC0708a) objNewInstance : null;
            return interfaceC0708a == null ? C() : interfaceC0708a;
        } catch (ClassNotFoundException unused) {
            return C();
        } catch (IllegalAccessException e3) {
            throw new RuntimeException("No ReactModuleInfoProvider for MainReactPackage$$ReactModuleInfoProvider", e3);
        } catch (InstantiationException e4) {
            throw new RuntimeException("No ReactModuleInfoProvider for MainReactPackage$$ReactModuleInfoProvider", e4);
        }
    }

    @Override // c1.AbstractC0329a
    public List j(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        return AbstractC0586n.T(this.f1422a.values());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Map D(Map map) {
        return map;
    }
}
