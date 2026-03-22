package p411e.p412a.p413a.p414u1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.CameraControl;
import androidx.camera.core.CameraInfo;
import androidx.camera.core.impl.CameraConfig;
import androidx.camera.core.impl.CameraConfigs;
import androidx.camera.core.impl.CameraInternal;
import java.util.Collections;
import java.util.LinkedHashSet;

/* renamed from: e.a.a.u1.p */
/* loaded from: classes.dex */
public final /* synthetic */ class C4276p {
    @NonNull
    /* renamed from: a */
    public static CameraControl m4847a(CameraInternal _this) {
        return _this.getCameraControlInternal();
    }

    @NonNull
    /* renamed from: b */
    public static CameraInfo m4848b(CameraInternal _this) {
        return _this.getCameraInfoInternal();
    }

    @NonNull
    /* renamed from: c */
    public static LinkedHashSet m4849c(CameraInternal _this) {
        return new LinkedHashSet(Collections.singleton(_this));
    }

    @NonNull
    /* renamed from: d */
    public static CameraConfig m4850d(CameraInternal _this) {
        return CameraConfigs.emptyConfig();
    }

    /* renamed from: e */
    public static void m4851e(@Nullable CameraInternal cameraInternal, CameraConfig cameraConfig) {
    }
}
