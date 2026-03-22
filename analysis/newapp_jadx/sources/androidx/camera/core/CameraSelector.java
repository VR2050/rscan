package androidx.camera.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.experimental.UseExperimental;
import androidx.camera.core.impl.CameraInternal;
import androidx.camera.core.impl.LensFacingCameraFilter;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Iterator;
import java.util.LinkedHashSet;

/* loaded from: classes.dex */
public final class CameraSelector {
    public static final int LENS_FACING_BACK = 1;
    public static final int LENS_FACING_FRONT = 0;
    private LinkedHashSet<CameraFilter> mCameraFilterSet;

    @NonNull
    public static final CameraSelector DEFAULT_FRONT_CAMERA = new Builder().requireLensFacing(0).build();

    @NonNull
    public static final CameraSelector DEFAULT_BACK_CAMERA = new Builder().requireLensFacing(1).build();

    @Retention(RetentionPolicy.SOURCE)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public @interface LensFacing {
    }

    public CameraSelector(LinkedHashSet<CameraFilter> linkedHashSet) {
        this.mCameraFilterSet = linkedHashSet;
    }

    @NonNull
    @UseExperimental(markerClass = ExperimentalCameraFilter.class)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public LinkedHashSet<CameraInternal> filter(@NonNull LinkedHashSet<CameraInternal> linkedHashSet) {
        LinkedHashSet linkedHashSet2 = new LinkedHashSet(linkedHashSet);
        LinkedHashSet<Camera> linkedHashSet3 = new LinkedHashSet<>(linkedHashSet);
        Iterator<CameraFilter> it = this.mCameraFilterSet.iterator();
        while (it.hasNext()) {
            linkedHashSet3 = it.next().filter(linkedHashSet3);
            if (linkedHashSet3.isEmpty()) {
                throw new IllegalArgumentException("No available camera can be found.");
            }
            if (!linkedHashSet2.containsAll(linkedHashSet3)) {
                throw new IllegalArgumentException("The output isn't contained in the input.");
            }
            linkedHashSet2.retainAll(linkedHashSet3);
        }
        LinkedHashSet<CameraInternal> linkedHashSet4 = new LinkedHashSet<>();
        Iterator<Camera> it2 = linkedHashSet3.iterator();
        while (it2.hasNext()) {
            linkedHashSet4.add((CameraInternal) it2.next());
        }
        return linkedHashSet4;
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public LinkedHashSet<CameraFilter> getCameraFilterSet() {
        return this.mCameraFilterSet;
    }

    @Nullable
    @UseExperimental(markerClass = ExperimentalCameraFilter.class)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public Integer getLensFacing() {
        Iterator<CameraFilter> it = this.mCameraFilterSet.iterator();
        Integer num = null;
        while (it.hasNext()) {
            CameraFilter next = it.next();
            if (next instanceof LensFacingCameraFilter) {
                Integer valueOf = Integer.valueOf(((LensFacingCameraFilter) next).getLensFacing());
                if (num == null) {
                    num = valueOf;
                } else if (!num.equals(valueOf)) {
                    throw new IllegalStateException("Multiple conflicting lens facing requirements exist.");
                }
            }
        }
        return num;
    }

    @NonNull
    @UseExperimental(markerClass = ExperimentalCameraFilter.class)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public CameraInternal select(@NonNull LinkedHashSet<CameraInternal> linkedHashSet) {
        return filter(linkedHashSet).iterator().next();
    }

    public static final class Builder {
        private final LinkedHashSet<CameraFilter> mCameraFilterSet;

        public Builder() {
            this.mCameraFilterSet = new LinkedHashSet<>();
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public static Builder fromSelector(@NonNull CameraSelector cameraSelector) {
            return new Builder(cameraSelector.getCameraFilterSet());
        }

        @NonNull
        @ExperimentalCameraFilter
        public Builder addCameraFilter(@NonNull CameraFilter cameraFilter) {
            this.mCameraFilterSet.add(cameraFilter);
            return this;
        }

        @NonNull
        public CameraSelector build() {
            return new CameraSelector(this.mCameraFilterSet);
        }

        @NonNull
        @UseExperimental(markerClass = ExperimentalCameraFilter.class)
        public Builder requireLensFacing(int i2) {
            this.mCameraFilterSet.add(new LensFacingCameraFilter(i2));
            return this;
        }

        private Builder(@NonNull LinkedHashSet<CameraFilter> linkedHashSet) {
            this.mCameraFilterSet = new LinkedHashSet<>(linkedHashSet);
        }
    }
}
