package p411e.p412a.p413a.p417v1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.internal.TargetConfig;

/* renamed from: e.a.a.v1.b */
/* loaded from: classes.dex */
public final /* synthetic */ class C4286b {
    @NonNull
    /* renamed from: a */
    public static Class m4888a(TargetConfig _this) {
        return (Class) _this.retrieveOption(TargetConfig.OPTION_TARGET_CLASS);
    }

    @Nullable
    /* renamed from: b */
    public static Class m4889b(@Nullable TargetConfig _this, Class cls) {
        return (Class) _this.retrieveOption(TargetConfig.OPTION_TARGET_CLASS, cls);
    }

    @NonNull
    /* renamed from: c */
    public static String m4890c(TargetConfig _this) {
        return (String) _this.retrieveOption(TargetConfig.OPTION_TARGET_NAME);
    }

    @Nullable
    /* renamed from: d */
    public static String m4891d(@Nullable TargetConfig _this, String str) {
        return (String) _this.retrieveOption(TargetConfig.OPTION_TARGET_NAME, str);
    }
}
