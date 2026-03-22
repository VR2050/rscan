package androidx.camera.core;

import androidx.annotation.NonNull;
import androidx.camera.core.impl.TagBundle;

/* loaded from: classes.dex */
public abstract class ImmutableImageInfo implements ImageInfo {
    public static ImageInfo create(@NonNull TagBundle tagBundle, long j2, int i2) {
        return new AutoValue_ImmutableImageInfo(tagBundle, j2, i2);
    }

    @Override // androidx.camera.core.ImageInfo
    public abstract int getRotationDegrees();

    @Override // androidx.camera.core.ImageInfo
    @NonNull
    public abstract TagBundle getTagBundle();

    @Override // androidx.camera.core.ImageInfo
    public abstract long getTimestamp();
}
