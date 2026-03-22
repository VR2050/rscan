package androidx.camera.core.impl;

import androidx.annotation.NonNull;
import androidx.annotation.experimental.UseExperimental;
import androidx.camera.core.Camera;
import androidx.camera.core.CameraFilter;
import androidx.camera.core.ExperimentalCameraFilter;
import androidx.core.util.Preconditions;
import java.util.Iterator;
import java.util.LinkedHashSet;

@UseExperimental(markerClass = ExperimentalCameraFilter.class)
/* loaded from: classes.dex */
public class LensFacingCameraFilter implements CameraFilter {
    private int mLensFacing;

    public LensFacingCameraFilter(int i2) {
        this.mLensFacing = i2;
    }

    @Override // androidx.camera.core.CameraFilter
    @NonNull
    public LinkedHashSet<Camera> filter(@NonNull LinkedHashSet<Camera> linkedHashSet) {
        LinkedHashSet<Camera> linkedHashSet2 = new LinkedHashSet<>();
        Iterator<Camera> it = linkedHashSet.iterator();
        while (it.hasNext()) {
            Camera next = it.next();
            Preconditions.checkState(next instanceof CameraInternal, "The camera doesn't contain internal implementation.");
            Integer lensFacing = ((CameraInternal) next).getCameraInfoInternal().getLensFacing();
            if (lensFacing != null && lensFacing.intValue() == this.mLensFacing) {
                linkedHashSet2.add(next);
            }
        }
        return linkedHashSet2;
    }

    public int getLensFacing() {
        return this.mLensFacing;
    }
}
