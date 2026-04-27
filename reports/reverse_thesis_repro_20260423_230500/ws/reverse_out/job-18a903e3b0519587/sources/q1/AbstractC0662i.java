package q1;

/* JADX INFO: renamed from: q1.i, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0662i extends AbstractC0658e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f9922a;

    public AbstractC0662i(boolean z3) {
        this.f9922a = z3;
    }

    @Override // com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean enableBridgelessArchitecture() {
        return this.f9922a;
    }

    @Override // q1.AbstractC0658e, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useNativeViewConfigsInBridgelessMode() {
        return this.f9922a || super.useNativeViewConfigsInBridgelessMode();
    }

    @Override // q1.AbstractC0658e, com.facebook.react.internal.featureflags.ReactNativeFeatureFlagsProvider
    public boolean useTurboModuleInterop() {
        return this.f9922a || super.useTurboModuleInterop();
    }
}
