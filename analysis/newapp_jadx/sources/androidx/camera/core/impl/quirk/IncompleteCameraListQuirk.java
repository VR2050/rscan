package androidx.camera.core.impl.quirk;

import android.os.Build;
import androidx.camera.core.impl.Quirk;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes.dex */
public class IncompleteCameraListQuirk implements Quirk {
    private static final List<String> KNOWN_AFFECTED_DEVICES = new ArrayList(Arrays.asList("a5y17lte", "tb-8704x", "a7y17lte", "on7xelte", "heroqltevzw", "1816", "1814", "1815", "santoni", "htc_oclul", "asus_z01h_1", "vox_alpha_plus", "a5y17ltecan", "x304l", "hero2qltevzw", "a5y17lteskt", "1801", "a5y17lteskt", "1801", "a5y17ltelgt", "herolte", "htc_hiau_ml_tuhl", "a6plte", "hwtrt-q", "co2_sprout", "h3223", "davinci", "vince", "armor_x5"));

    private IncompleteCameraListQuirk() {
    }

    public static boolean isCurrentDeviceAffected() {
        return KNOWN_AFFECTED_DEVICES.contains(Build.DEVICE.toLowerCase());
    }
}
