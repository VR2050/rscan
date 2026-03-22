package androidx.camera.view.video;

import android.net.Uri;
import androidx.annotation.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class AutoValue_OutputFileResults extends OutputFileResults {
    private final Uri savedUri;

    public AutoValue_OutputFileResults(@Nullable Uri uri) {
        this.savedUri = uri;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof OutputFileResults)) {
            return false;
        }
        Uri uri = this.savedUri;
        Uri savedUri = ((OutputFileResults) obj).getSavedUri();
        return uri == null ? savedUri == null : uri.equals(savedUri);
    }

    @Override // androidx.camera.view.video.OutputFileResults
    @Nullable
    public Uri getSavedUri() {
        return this.savedUri;
    }

    public int hashCode() {
        Uri uri = this.savedUri;
        return (uri == null ? 0 : uri.hashCode()) ^ 1000003;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("OutputFileResults{savedUri=");
        m586H.append(this.savedUri);
        m586H.append("}");
        return m586H.toString();
    }
}
