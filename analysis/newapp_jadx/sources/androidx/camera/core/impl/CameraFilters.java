package androidx.camera.core.impl;

import androidx.camera.core.CameraFilter;
import androidx.camera.core.impl.CameraFilters;
import java.util.LinkedHashSet;

/* loaded from: classes.dex */
public class CameraFilters {
    public static final CameraFilter ANY = new CameraFilter() { // from class: e.a.a.u1.b
        @Override // androidx.camera.core.CameraFilter
        public final LinkedHashSet filter(LinkedHashSet linkedHashSet) {
            CameraFilter cameraFilter = CameraFilters.ANY;
            return linkedHashSet;
        }
    };
    public static final CameraFilter NONE = new CameraFilter() { // from class: e.a.a.u1.a
        @Override // androidx.camera.core.CameraFilter
        public final LinkedHashSet filter(LinkedHashSet linkedHashSet) {
            CameraFilter cameraFilter = CameraFilters.ANY;
            return new LinkedHashSet();
        }
    };

    private CameraFilters() {
    }
}
