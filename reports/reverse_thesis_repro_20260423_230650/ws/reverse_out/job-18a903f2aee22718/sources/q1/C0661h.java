package q1;

/* JADX INFO: renamed from: q1.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0661h extends AbstractC0662i {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f9919b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f9920c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f9921d;

    public C0661h(boolean z3, boolean z4, boolean z5) {
        super(z4);
        this.f9919b = z3;
        this.f9920c = z4;
        this.f9921d = z5;
    }

    @Override // com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableFabricRenderer() {
        return this.f9920c || this.f9919b;
    }

    @Override // q1.AbstractC0658e, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean updateRuntimeShadowNodeReferencesOnCommit() {
        return true;
    }

    @Override // com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useFabricInterop() {
        return this.f9920c || this.f9919b;
    }

    @Override // q1.AbstractC0658e, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useShadowNodeStateOnClone() {
        return true;
    }

    @Override // com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useTurboModules() {
        return this.f9920c || this.f9921d;
    }
}
