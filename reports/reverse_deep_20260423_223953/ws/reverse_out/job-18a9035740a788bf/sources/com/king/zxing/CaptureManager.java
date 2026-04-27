package com.king.zxing;

import com.king.zxing.camera.CameraManager;

/* JADX INFO: loaded from: classes3.dex */
public interface CaptureManager {
    AmbientLightManager getAmbientLightManager();

    BeepManager getBeepManager();

    CameraManager getCameraManager();

    InactivityTimer getInactivityTimer();
}
