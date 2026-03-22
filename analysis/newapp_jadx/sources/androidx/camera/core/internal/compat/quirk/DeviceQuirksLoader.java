package androidx.camera.core.internal.compat.quirk;

import androidx.annotation.NonNull;
import androidx.camera.core.impl.Quirk;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public class DeviceQuirksLoader {
    private DeviceQuirksLoader() {
    }

    @NonNull
    public static List<Quirk> loadQuirks() {
        ArrayList arrayList = new ArrayList();
        if (HuaweiMediaStoreLocationValidationQuirk.load()) {
            arrayList.add(new HuaweiMediaStoreLocationValidationQuirk());
        }
        return arrayList;
    }
}
