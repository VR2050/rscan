package androidx.camera.core.impl;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.Logger;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class CameraValidator {
    private static final String TAG = "CameraValidator";

    public static class CameraIdListIncorrectException extends Exception {
        public CameraIdListIncorrectException(@Nullable String str, @Nullable Throwable th) {
            super(str, th);
        }
    }

    private CameraValidator() {
    }

    public static void validateCameras(@NonNull Context context, @NonNull CameraRepository cameraRepository) {
        PackageManager packageManager = context.getPackageManager();
        StringBuilder m586H = C1499a.m586H("Verifying camera lens facing on ");
        m586H.append(Build.DEVICE);
        Logger.m123d(TAG, m586H.toString());
        try {
            if (packageManager.hasSystemFeature("android.hardware.camera")) {
                CameraSelector.DEFAULT_BACK_CAMERA.select(cameraRepository.getCameras());
            }
            if (packageManager.hasSystemFeature("android.hardware.camera.front")) {
                CameraSelector.DEFAULT_FRONT_CAMERA.select(cameraRepository.getCameras());
            }
        } catch (IllegalArgumentException e2) {
            StringBuilder m586H2 = C1499a.m586H("Camera LensFacing verification failed, existing cameras: ");
            m586H2.append(cameraRepository.getCameras());
            Logger.m125e(TAG, m586H2.toString());
            throw new CameraIdListIncorrectException("Expected camera missing from device.", e2);
        }
    }
}
