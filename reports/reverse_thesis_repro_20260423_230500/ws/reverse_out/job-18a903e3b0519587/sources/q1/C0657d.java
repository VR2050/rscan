package q1;

import com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsCxxInterop;
import com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider;
import t2.j;

/* JADX INFO: renamed from: q1.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0657d implements InterfaceC0656c {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private Boolean f9874A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private Boolean f9875B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private Boolean f9876C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private Boolean f9877D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private Boolean f9878E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private Boolean f9879F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private Boolean f9880G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private Boolean f9881H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private Boolean f9882I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private Boolean f9883J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private Boolean f9884K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private Boolean f9885L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private Boolean f9886M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    private Boolean f9887N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    private Boolean f9888O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    private Boolean f9889P;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private Boolean f9890Q;

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    private Boolean f9891R;

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    private Boolean f9892S;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Boolean f9893a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Boolean f9894b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Boolean f9895c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Boolean f9896d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Boolean f9897e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Boolean f9898f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Boolean f9899g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Boolean f9900h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private Boolean f9901i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private Boolean f9902j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Boolean f9903k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Boolean f9904l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private Boolean f9905m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private Boolean f9906n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private Boolean f9907o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private Boolean f9908p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private Boolean f9909q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private Boolean f9910r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private Boolean f9911s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private Boolean f9912t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private Boolean f9913u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private Boolean f9914v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private Boolean f9915w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private Boolean f9916x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private Boolean f9917y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private Boolean f9918z;

    @Override // q1.InterfaceC0656c
    public void a(ReactNativeFeatureFlagsProvider reactNativeFeatureFlagsProvider) {
        j.f(reactNativeFeatureFlagsProvider, "provider");
        ReactNativeFeatureFlagsCxxInterop.override(reactNativeFeatureFlagsProvider);
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean commonTestFlag() {
        Boolean boolValueOf = this.f9893a;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.commonTestFlag());
            this.f9893a = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean disableMountItemReorderingAndroid() {
        Boolean boolValueOf = this.f9894b;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.disableMountItemReorderingAndroid());
            this.f9894b = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableAccumulatedUpdatesInRawPropsAndroid() {
        Boolean boolValueOf = this.f9895c;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableAccumulatedUpdatesInRawPropsAndroid());
            this.f9895c = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableBridgelessArchitecture() {
        Boolean boolValueOf = this.f9896d;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableBridgelessArchitecture());
            this.f9896d = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableCppPropsIteratorSetter() {
        Boolean boolValueOf = this.f9897e;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableCppPropsIteratorSetter());
            this.f9897e = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableEagerRootViewAttachment() {
        Boolean boolValueOf = this.f9898f;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableEagerRootViewAttachment());
            this.f9898f = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableFabricLogs() {
        Boolean boolValueOf = this.f9899g;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableFabricLogs());
            this.f9899g = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableFabricRenderer() {
        Boolean boolValueOf = this.f9900h;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableFabricRenderer());
            this.f9900h = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableIOSViewClipToPaddingBox() {
        Boolean boolValueOf = this.f9901i;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableIOSViewClipToPaddingBox());
            this.f9901i = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableImagePrefetchingAndroid() {
        Boolean boolValueOf = this.f9902j;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableImagePrefetchingAndroid());
            this.f9902j = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableJSRuntimeGCOnMemoryPressureOnIOS() {
        Boolean boolValueOf = this.f9903k;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableJSRuntimeGCOnMemoryPressureOnIOS());
            this.f9903k = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableLayoutAnimationsOnAndroid() {
        Boolean boolValueOf = this.f9904l;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableLayoutAnimationsOnAndroid());
            this.f9904l = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableLayoutAnimationsOnIOS() {
        Boolean boolValueOf = this.f9905m;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableLayoutAnimationsOnIOS());
            this.f9905m = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableLongTaskAPI() {
        Boolean boolValueOf = this.f9906n;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableLongTaskAPI());
            this.f9906n = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableNativeCSSParsing() {
        Boolean boolValueOf = this.f9907o;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableNativeCSSParsing());
            this.f9907o = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableNewBackgroundAndBorderDrawables() {
        Boolean boolValueOf = this.f9908p;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableNewBackgroundAndBorderDrawables());
            this.f9908p = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enablePreciseSchedulingForPremountItemsOnAndroid() {
        Boolean boolValueOf = this.f9909q;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enablePreciseSchedulingForPremountItemsOnAndroid());
            this.f9909q = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enablePropsUpdateReconciliationAndroid() {
        Boolean boolValueOf = this.f9910r;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enablePropsUpdateReconciliationAndroid());
            this.f9910r = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableReportEventPaintTime() {
        Boolean boolValueOf = this.f9911s;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableReportEventPaintTime());
            this.f9911s = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableSynchronousStateUpdates() {
        Boolean boolValueOf = this.f9912t;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableSynchronousStateUpdates());
            this.f9912t = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableUIConsistency() {
        Boolean boolValueOf = this.f9913u;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableUIConsistency());
            this.f9913u = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableViewCulling() {
        Boolean boolValueOf = this.f9914v;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableViewCulling());
            this.f9914v = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableViewRecycling() {
        Boolean boolValueOf = this.f9915w;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableViewRecycling());
            this.f9915w = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableViewRecyclingForText() {
        Boolean boolValueOf = this.f9916x;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableViewRecyclingForText());
            this.f9916x = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableViewRecyclingForView() {
        Boolean boolValueOf = this.f9917y;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.enableViewRecyclingForView());
            this.f9917y = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean excludeYogaFromRawProps() {
        Boolean boolValueOf = this.f9918z;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.excludeYogaFromRawProps());
            this.f9918z = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean fixDifferentiatorEmittingUpdatesWithWrongParentTag() {
        Boolean boolValueOf = this.f9874A;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.fixDifferentiatorEmittingUpdatesWithWrongParentTag());
            this.f9874A = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean fixMappingOfEventPrioritiesBetweenFabricAndReact() {
        Boolean boolValueOf = this.f9875B;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.fixMappingOfEventPrioritiesBetweenFabricAndReact());
            this.f9875B = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean fixMountingCoordinatorReportedPendingTransactionsOnAndroid() {
        Boolean boolValueOf = this.f9876C;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.fixMountingCoordinatorReportedPendingTransactionsOnAndroid());
            this.f9876C = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean fuseboxEnabledRelease() {
        Boolean boolValueOf = this.f9877D;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.fuseboxEnabledRelease());
            this.f9877D = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean fuseboxNetworkInspectionEnabled() {
        Boolean boolValueOf = this.f9878E;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.fuseboxNetworkInspectionEnabled());
            this.f9878E = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean lazyAnimationCallbacks() {
        Boolean boolValueOf = this.f9879F;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.lazyAnimationCallbacks());
            this.f9879F = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean removeTurboModuleManagerDelegateMutex() {
        Boolean boolValueOf = this.f9880G;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.removeTurboModuleManagerDelegateMutex());
            this.f9880G = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean throwExceptionInsteadOfDeadlockOnTurboModuleSetupDuringSyncRenderIOS() {
        Boolean boolValueOf = this.f9881H;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.throwExceptionInsteadOfDeadlockOnTurboModuleSetupDuringSyncRenderIOS());
            this.f9881H = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean traceTurboModulePromiseRejectionsOnAndroid() {
        Boolean boolValueOf = this.f9882I;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.traceTurboModulePromiseRejectionsOnAndroid());
            this.f9882I = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean updateRuntimeShadowNodeReferencesOnCommit() {
        Boolean boolValueOf = this.f9883J;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.updateRuntimeShadowNodeReferencesOnCommit());
            this.f9883J = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useAlwaysAvailableJSErrorHandling() {
        Boolean boolValueOf = this.f9884K;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useAlwaysAvailableJSErrorHandling());
            this.f9884K = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useEditTextStockAndroidFocusBehavior() {
        Boolean boolValueOf = this.f9885L;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useEditTextStockAndroidFocusBehavior());
            this.f9885L = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useFabricInterop() {
        Boolean boolValueOf = this.f9886M;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useFabricInterop());
            this.f9886M = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useNativeViewConfigsInBridgelessMode() {
        Boolean boolValueOf = this.f9887N;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useNativeViewConfigsInBridgelessMode());
            this.f9887N = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useOptimizedEventBatchingOnAndroid() {
        Boolean boolValueOf = this.f9888O;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useOptimizedEventBatchingOnAndroid());
            this.f9888O = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useRawPropsJsiValue() {
        Boolean boolValueOf = this.f9889P;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useRawPropsJsiValue());
            this.f9889P = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useShadowNodeStateOnClone() {
        Boolean boolValueOf = this.f9890Q;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useShadowNodeStateOnClone());
            this.f9890Q = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useTurboModuleInterop() {
        Boolean boolValueOf = this.f9891R;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useTurboModuleInterop());
            this.f9891R = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }

    @Override // q1.InterfaceC0656c, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useTurboModules() {
        Boolean boolValueOf = this.f9892S;
        if (boolValueOf == null) {
            boolValueOf = Boolean.valueOf(ReactNativeFeatureFlagsCxxInterop.useTurboModules());
            this.f9892S = boolValueOf;
        }
        return boolValueOf.booleanValue();
    }
}
