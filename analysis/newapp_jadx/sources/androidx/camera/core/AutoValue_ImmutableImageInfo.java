package androidx.camera.core;

import androidx.annotation.NonNull;
import androidx.camera.core.impl.TagBundle;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class AutoValue_ImmutableImageInfo extends ImmutableImageInfo {
    private final int rotationDegrees;
    private final TagBundle tagBundle;
    private final long timestamp;

    public AutoValue_ImmutableImageInfo(TagBundle tagBundle, long j2, int i2) {
        Objects.requireNonNull(tagBundle, "Null tagBundle");
        this.tagBundle = tagBundle;
        this.timestamp = j2;
        this.rotationDegrees = i2;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof ImmutableImageInfo)) {
            return false;
        }
        ImmutableImageInfo immutableImageInfo = (ImmutableImageInfo) obj;
        return this.tagBundle.equals(immutableImageInfo.getTagBundle()) && this.timestamp == immutableImageInfo.getTimestamp() && this.rotationDegrees == immutableImageInfo.getRotationDegrees();
    }

    @Override // androidx.camera.core.ImmutableImageInfo, androidx.camera.core.ImageInfo
    public int getRotationDegrees() {
        return this.rotationDegrees;
    }

    @Override // androidx.camera.core.ImmutableImageInfo, androidx.camera.core.ImageInfo
    @NonNull
    public TagBundle getTagBundle() {
        return this.tagBundle;
    }

    @Override // androidx.camera.core.ImmutableImageInfo, androidx.camera.core.ImageInfo
    public long getTimestamp() {
        return this.timestamp;
    }

    public int hashCode() {
        int hashCode = (this.tagBundle.hashCode() ^ 1000003) * 1000003;
        long j2 = this.timestamp;
        return ((hashCode ^ ((int) (j2 ^ (j2 >>> 32)))) * 1000003) ^ this.rotationDegrees;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ImmutableImageInfo{tagBundle=");
        m586H.append(this.tagBundle);
        m586H.append(", timestamp=");
        m586H.append(this.timestamp);
        m586H.append(", rotationDegrees=");
        return C1499a.m580B(m586H, this.rotationDegrees, "}");
    }
}
