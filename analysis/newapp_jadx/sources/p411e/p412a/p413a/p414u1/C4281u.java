package p411e.p412a.p413a.p414u1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.impl.CaptureConfig;
import androidx.camera.core.impl.SessionConfig;
import androidx.camera.core.impl.UseCaseConfig;

/* renamed from: e.a.a.u1.u */
/* loaded from: classes.dex */
public final /* synthetic */ class C4281u {
    @NonNull
    /* renamed from: a */
    public static CameraSelector m4874a(UseCaseConfig _this) {
        return (CameraSelector) _this.retrieveOption(UseCaseConfig.OPTION_CAMERA_SELECTOR);
    }

    @Nullable
    /* renamed from: b */
    public static CameraSelector m4875b(@Nullable UseCaseConfig _this, CameraSelector cameraSelector) {
        return (CameraSelector) _this.retrieveOption(UseCaseConfig.OPTION_CAMERA_SELECTOR, cameraSelector);
    }

    @NonNull
    /* renamed from: c */
    public static CaptureConfig.OptionUnpacker m4876c(UseCaseConfig _this) {
        return (CaptureConfig.OptionUnpacker) _this.retrieveOption(UseCaseConfig.OPTION_CAPTURE_CONFIG_UNPACKER);
    }

    @Nullable
    /* renamed from: d */
    public static CaptureConfig.OptionUnpacker m4877d(@Nullable UseCaseConfig _this, CaptureConfig.OptionUnpacker optionUnpacker) {
        return (CaptureConfig.OptionUnpacker) _this.retrieveOption(UseCaseConfig.OPTION_CAPTURE_CONFIG_UNPACKER, optionUnpacker);
    }

    @NonNull
    /* renamed from: e */
    public static CaptureConfig m4878e(UseCaseConfig _this) {
        return (CaptureConfig) _this.retrieveOption(UseCaseConfig.OPTION_DEFAULT_CAPTURE_CONFIG);
    }

    @Nullable
    /* renamed from: f */
    public static CaptureConfig m4879f(@Nullable UseCaseConfig _this, CaptureConfig captureConfig) {
        return (CaptureConfig) _this.retrieveOption(UseCaseConfig.OPTION_DEFAULT_CAPTURE_CONFIG, captureConfig);
    }

    @NonNull
    /* renamed from: g */
    public static SessionConfig m4880g(UseCaseConfig _this) {
        return (SessionConfig) _this.retrieveOption(UseCaseConfig.OPTION_DEFAULT_SESSION_CONFIG);
    }

    @Nullable
    /* renamed from: h */
    public static SessionConfig m4881h(@Nullable UseCaseConfig _this, SessionConfig sessionConfig) {
        return (SessionConfig) _this.retrieveOption(UseCaseConfig.OPTION_DEFAULT_SESSION_CONFIG, sessionConfig);
    }

    @NonNull
    /* renamed from: i */
    public static SessionConfig.OptionUnpacker m4882i(UseCaseConfig _this) {
        return (SessionConfig.OptionUnpacker) _this.retrieveOption(UseCaseConfig.OPTION_SESSION_CONFIG_UNPACKER);
    }

    @Nullable
    /* renamed from: j */
    public static SessionConfig.OptionUnpacker m4883j(@Nullable UseCaseConfig _this, SessionConfig.OptionUnpacker optionUnpacker) {
        return (SessionConfig.OptionUnpacker) _this.retrieveOption(UseCaseConfig.OPTION_SESSION_CONFIG_UNPACKER, optionUnpacker);
    }

    /* renamed from: k */
    public static int m4884k(UseCaseConfig _this) {
        return ((Integer) _this.retrieveOption(UseCaseConfig.OPTION_SURFACE_OCCUPANCY_PRIORITY)).intValue();
    }

    /* renamed from: l */
    public static int m4885l(UseCaseConfig _this, int i2) {
        return ((Integer) _this.retrieveOption(UseCaseConfig.OPTION_SURFACE_OCCUPANCY_PRIORITY, Integer.valueOf(i2))).intValue();
    }
}
