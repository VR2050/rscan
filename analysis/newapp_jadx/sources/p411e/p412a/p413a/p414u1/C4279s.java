package p411e.p412a.p413a.p414u1;

import android.util.Size;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.impl.ImageOutputConfig;
import java.util.List;

/* renamed from: e.a.a.u1.s */
/* loaded from: classes.dex */
public final /* synthetic */ class C4279s {
    @NonNull
    /* renamed from: a */
    public static Size m4854a(ImageOutputConfig _this) {
        return (Size) _this.retrieveOption(ImageOutputConfig.OPTION_DEFAULT_RESOLUTION);
    }

    @Nullable
    /* renamed from: b */
    public static Size m4855b(@Nullable ImageOutputConfig _this, Size size) {
        return (Size) _this.retrieveOption(ImageOutputConfig.OPTION_DEFAULT_RESOLUTION, size);
    }

    @NonNull
    /* renamed from: c */
    public static Size m4856c(ImageOutputConfig _this) {
        return (Size) _this.retrieveOption(ImageOutputConfig.OPTION_MAX_RESOLUTION);
    }

    @Nullable
    /* renamed from: d */
    public static Size m4857d(@Nullable ImageOutputConfig _this, Size size) {
        return (Size) _this.retrieveOption(ImageOutputConfig.OPTION_MAX_RESOLUTION, size);
    }

    @NonNull
    /* renamed from: e */
    public static List m4858e(ImageOutputConfig _this) {
        return (List) _this.retrieveOption(ImageOutputConfig.OPTION_SUPPORTED_RESOLUTIONS);
    }

    @Nullable
    /* renamed from: f */
    public static List m4859f(@Nullable ImageOutputConfig _this, List list) {
        return (List) _this.retrieveOption(ImageOutputConfig.OPTION_SUPPORTED_RESOLUTIONS, list);
    }

    /* renamed from: g */
    public static int m4860g(ImageOutputConfig _this) {
        return ((Integer) _this.retrieveOption(ImageOutputConfig.OPTION_TARGET_ASPECT_RATIO)).intValue();
    }

    @NonNull
    /* renamed from: h */
    public static Size m4861h(ImageOutputConfig _this) {
        return (Size) _this.retrieveOption(ImageOutputConfig.OPTION_TARGET_RESOLUTION);
    }

    @Nullable
    /* renamed from: i */
    public static Size m4862i(@Nullable ImageOutputConfig _this, Size size) {
        return (Size) _this.retrieveOption(ImageOutputConfig.OPTION_TARGET_RESOLUTION, size);
    }

    /* renamed from: j */
    public static int m4863j(ImageOutputConfig _this) {
        return ((Integer) _this.retrieveOption(ImageOutputConfig.OPTION_TARGET_ROTATION)).intValue();
    }

    /* renamed from: k */
    public static int m4864k(ImageOutputConfig _this, int i2) {
        return ((Integer) _this.retrieveOption(ImageOutputConfig.OPTION_TARGET_ROTATION, Integer.valueOf(i2))).intValue();
    }

    /* renamed from: l */
    public static boolean m4865l(ImageOutputConfig _this) {
        return _this.containsOption(ImageOutputConfig.OPTION_TARGET_ASPECT_RATIO);
    }
}
