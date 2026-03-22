package androidx.camera.core;

import androidx.annotation.NonNull;
import java.util.LinkedHashSet;

@ExperimentalCameraFilter
/* loaded from: classes.dex */
public interface CameraFilter {
    @NonNull
    LinkedHashSet<Camera> filter(@NonNull LinkedHashSet<Camera> linkedHashSet);
}
