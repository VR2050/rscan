package androidx.camera.core;

import androidx.annotation.FloatRange;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public interface CameraControl {

    public static final class OperationCanceledException extends Exception {
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public OperationCanceledException(@NonNull String str) {
            super(str);
        }

        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public OperationCanceledException(@NonNull String str, @NonNull Throwable th) {
            super(str, th);
        }
    }

    @NonNull
    InterfaceFutureC2413a<Void> cancelFocusAndMetering();

    @NonNull
    InterfaceFutureC2413a<Void> enableTorch(boolean z);

    @NonNull
    @ExperimentalExposureCompensation
    InterfaceFutureC2413a<Integer> setExposureCompensationIndex(int i2);

    @NonNull
    InterfaceFutureC2413a<Void> setLinearZoom(@FloatRange(from = 0.0d, m110to = 1.0d) float f2);

    @NonNull
    InterfaceFutureC2413a<Void> setZoomRatio(float f2);

    @NonNull
    InterfaceFutureC2413a<FocusMeteringResult> startFocusAndMetering(@NonNull FocusMeteringAction focusMeteringAction);
}
