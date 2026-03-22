package androidx.camera.core.impl;

import android.os.Handler;
import androidx.annotation.NonNull;
import java.util.Objects;
import java.util.concurrent.Executor;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class AutoValue_CameraThreadConfig extends CameraThreadConfig {
    private final Executor cameraExecutor;
    private final Handler schedulerHandler;

    public AutoValue_CameraThreadConfig(Executor executor, Handler handler) {
        Objects.requireNonNull(executor, "Null cameraExecutor");
        this.cameraExecutor = executor;
        Objects.requireNonNull(handler, "Null schedulerHandler");
        this.schedulerHandler = handler;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof CameraThreadConfig)) {
            return false;
        }
        CameraThreadConfig cameraThreadConfig = (CameraThreadConfig) obj;
        return this.cameraExecutor.equals(cameraThreadConfig.getCameraExecutor()) && this.schedulerHandler.equals(cameraThreadConfig.getSchedulerHandler());
    }

    @Override // androidx.camera.core.impl.CameraThreadConfig
    @NonNull
    public Executor getCameraExecutor() {
        return this.cameraExecutor;
    }

    @Override // androidx.camera.core.impl.CameraThreadConfig
    @NonNull
    public Handler getSchedulerHandler() {
        return this.schedulerHandler;
    }

    public int hashCode() {
        return ((this.cameraExecutor.hashCode() ^ 1000003) * 1000003) ^ this.schedulerHandler.hashCode();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("CameraThreadConfig{cameraExecutor=");
        m586H.append(this.cameraExecutor);
        m586H.append(", schedulerHandler=");
        m586H.append(this.schedulerHandler);
        m586H.append("}");
        return m586H.toString();
    }
}
