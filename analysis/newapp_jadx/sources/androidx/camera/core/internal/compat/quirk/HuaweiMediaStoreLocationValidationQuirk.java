package androidx.camera.core.internal.compat.quirk;

import android.os.Build;
import androidx.camera.core.impl.Quirk;

/* loaded from: classes.dex */
public class HuaweiMediaStoreLocationValidationQuirk implements Quirk {
    public static boolean load() {
        String str = Build.BRAND;
        return "HUAWEI".equals(str.toUpperCase()) || "HONOR".equals(str.toUpperCase());
    }

    public boolean canSaveToMediaStore() {
        return true;
    }
}
