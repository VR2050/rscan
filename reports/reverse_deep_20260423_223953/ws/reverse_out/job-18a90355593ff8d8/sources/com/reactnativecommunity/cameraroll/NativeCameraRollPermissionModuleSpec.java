package com.reactnativecommunity.cameraroll;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;

/* JADX INFO: loaded from: classes.dex */
public abstract class NativeCameraRollPermissionModuleSpec extends ReactContextBaseJavaModule implements TurboModule {
    public static final String NAME = "RNCCameraRollPermission";

    public NativeCameraRollPermissionModuleSpec(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @ReactMethod
    public abstract void addListener(String str);

    @ReactMethod
    public abstract void checkPermission(String str, Promise promise);

    @Override // com.facebook.react.bridge.NativeModule
    public String getName() {
        return NAME;
    }

    @ReactMethod
    public abstract void refreshPhotoSelection(Promise promise);

    @ReactMethod
    public abstract void removeListeners(double d3);

    @ReactMethod
    public abstract void requestAddOnlyPermission(Promise promise);

    @ReactMethod
    public abstract void requestReadWritePermission(Promise promise);
}
