package androidx.camera.core;

import android.view.Surface;
import androidx.annotation.NonNull;
import androidx.camera.core.SurfaceRequest;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class AutoValue_SurfaceRequest_Result extends SurfaceRequest.Result {
    private final int resultCode;
    private final Surface surface;

    public AutoValue_SurfaceRequest_Result(int i2, Surface surface) {
        this.resultCode = i2;
        Objects.requireNonNull(surface, "Null surface");
        this.surface = surface;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof SurfaceRequest.Result)) {
            return false;
        }
        SurfaceRequest.Result result = (SurfaceRequest.Result) obj;
        return this.resultCode == result.getResultCode() && this.surface.equals(result.getSurface());
    }

    @Override // androidx.camera.core.SurfaceRequest.Result
    public int getResultCode() {
        return this.resultCode;
    }

    @Override // androidx.camera.core.SurfaceRequest.Result
    @NonNull
    public Surface getSurface() {
        return this.surface;
    }

    public int hashCode() {
        return ((this.resultCode ^ 1000003) * 1000003) ^ this.surface.hashCode();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Result{resultCode=");
        m586H.append(this.resultCode);
        m586H.append(", surface=");
        m586H.append(this.surface);
        m586H.append("}");
        return m586H.toString();
    }
}
