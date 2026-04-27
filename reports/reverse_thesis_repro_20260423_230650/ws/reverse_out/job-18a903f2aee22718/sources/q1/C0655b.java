package q1;

import com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider;
import s2.InterfaceC0688a;
import t2.j;

/* JADX INFO: renamed from: q1.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0655b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0655b f9871a = new C0655b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static InterfaceC0688a f9872b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static InterfaceC0656c f9873c;

    static {
        InterfaceC0688a interfaceC0688a = new InterfaceC0688a() { // from class: q1.a
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return C0655b.b();
            }
        };
        f9872b = interfaceC0688a;
        f9873c = (InterfaceC0656c) interfaceC0688a.a();
    }

    private C0655b() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C0657d b() {
        return new C0657d();
    }

    public static final boolean c() {
        return f9873c.enableBridgelessArchitecture();
    }

    public static final boolean d() {
        return f9873c.enableEagerRootViewAttachment();
    }

    public static final boolean e() {
        return f9873c.enableFabricLogs();
    }

    public static final boolean f() {
        return f9873c.enableFabricRenderer();
    }

    public static final boolean g() {
        return f9873c.enableImagePrefetchingAndroid();
    }

    public static final boolean h() {
        return f9873c.enableNewBackgroundAndBorderDrawables();
    }

    public static final boolean i() {
        return f9873c.enablePreciseSchedulingForPremountItemsOnAndroid();
    }

    public static final boolean j() {
        return f9873c.enableViewRecycling();
    }

    public static final boolean k() {
        return f9873c.enableViewRecyclingForText();
    }

    public static final boolean l() {
        return f9873c.enableViewRecyclingForView();
    }

    public static final boolean m() {
        return f9873c.lazyAnimationCallbacks();
    }

    public static final void n(ReactNativeFeatureFlagsProvider reactNativeFeatureFlagsProvider) {
        j.f(reactNativeFeatureFlagsProvider, "provider");
        f9873c.a(reactNativeFeatureFlagsProvider);
    }

    public static final boolean o() {
        return f9873c.useEditTextStockAndroidFocusBehavior();
    }

    public static final boolean p() {
        return f9873c.useFabricInterop();
    }

    public static final boolean q() {
        return f9873c.useNativeViewConfigsInBridgelessMode();
    }

    public static final boolean r() {
        return f9873c.useOptimizedEventBatchingOnAndroid();
    }

    public static final boolean s() {
        return f9873c.useTurboModuleInterop();
    }

    public static final boolean t() {
        return f9873c.useTurboModules();
    }
}
