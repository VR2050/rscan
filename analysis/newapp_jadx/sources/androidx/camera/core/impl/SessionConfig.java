package androidx.camera.core.impl;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import androidx.annotation.NonNull;
import androidx.camera.core.Logger;
import androidx.camera.core.impl.CaptureConfig;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class SessionConfig {
    private final List<CameraDevice.StateCallback> mDeviceStateCallbacks;
    private final List<ErrorListener> mErrorListeners;
    private final CaptureConfig mRepeatingCaptureConfig;
    private final List<CameraCaptureSession.StateCallback> mSessionStateCallbacks;
    private final List<CameraCaptureCallback> mSingleCameraCaptureCallbacks;
    private final List<DeferrableSurface> mSurfaces;

    public static class BaseBuilder {
        public final Set<DeferrableSurface> mSurfaces = new HashSet();
        public final CaptureConfig.Builder mCaptureConfigBuilder = new CaptureConfig.Builder();
        public final List<CameraDevice.StateCallback> mDeviceStateCallbacks = new ArrayList();
        public final List<CameraCaptureSession.StateCallback> mSessionStateCallbacks = new ArrayList();
        public final List<ErrorListener> mErrorListeners = new ArrayList();
        public final List<CameraCaptureCallback> mSingleCameraCaptureCallbacks = new ArrayList();
    }

    public static class Builder extends BaseBuilder {
        @NonNull
        public static Builder createFrom(@NonNull UseCaseConfig<?> useCaseConfig) {
            OptionUnpacker sessionOptionUnpacker = useCaseConfig.getSessionOptionUnpacker(null);
            if (sessionOptionUnpacker != null) {
                Builder builder = new Builder();
                sessionOptionUnpacker.unpack(useCaseConfig, builder);
                return builder;
            }
            StringBuilder m586H = C1499a.m586H("Implementation is missing option unpacker for ");
            m586H.append(useCaseConfig.getTargetName(useCaseConfig.toString()));
            throw new IllegalStateException(m586H.toString());
        }

        public void addAllCameraCaptureCallbacks(@NonNull Collection<CameraCaptureCallback> collection) {
            this.mCaptureConfigBuilder.addAllCameraCaptureCallbacks(collection);
            this.mSingleCameraCaptureCallbacks.addAll(collection);
        }

        public void addAllDeviceStateCallbacks(@NonNull Collection<CameraDevice.StateCallback> collection) {
            Iterator<CameraDevice.StateCallback> it = collection.iterator();
            while (it.hasNext()) {
                addDeviceStateCallback(it.next());
            }
        }

        public void addAllRepeatingCameraCaptureCallbacks(@NonNull Collection<CameraCaptureCallback> collection) {
            this.mCaptureConfigBuilder.addAllCameraCaptureCallbacks(collection);
        }

        public void addAllSessionStateCallbacks(@NonNull List<CameraCaptureSession.StateCallback> list) {
            Iterator<CameraCaptureSession.StateCallback> it = list.iterator();
            while (it.hasNext()) {
                addSessionStateCallback(it.next());
            }
        }

        public void addCameraCaptureCallback(@NonNull CameraCaptureCallback cameraCaptureCallback) {
            this.mCaptureConfigBuilder.addCameraCaptureCallback(cameraCaptureCallback);
            this.mSingleCameraCaptureCallbacks.add(cameraCaptureCallback);
        }

        public void addDeviceStateCallback(@NonNull CameraDevice.StateCallback stateCallback) {
            if (this.mDeviceStateCallbacks.contains(stateCallback)) {
                throw new IllegalArgumentException("Duplicate device state callback.");
            }
            this.mDeviceStateCallbacks.add(stateCallback);
        }

        public void addErrorListener(@NonNull ErrorListener errorListener) {
            this.mErrorListeners.add(errorListener);
        }

        public void addImplementationOptions(@NonNull Config config) {
            this.mCaptureConfigBuilder.addImplementationOptions(config);
        }

        public void addNonRepeatingSurface(@NonNull DeferrableSurface deferrableSurface) {
            this.mSurfaces.add(deferrableSurface);
        }

        public void addRepeatingCameraCaptureCallback(@NonNull CameraCaptureCallback cameraCaptureCallback) {
            this.mCaptureConfigBuilder.addCameraCaptureCallback(cameraCaptureCallback);
        }

        public void addSessionStateCallback(@NonNull CameraCaptureSession.StateCallback stateCallback) {
            if (this.mSessionStateCallbacks.contains(stateCallback)) {
                throw new IllegalArgumentException("Duplicate session state callback.");
            }
            this.mSessionStateCallbacks.add(stateCallback);
        }

        public void addSurface(@NonNull DeferrableSurface deferrableSurface) {
            this.mSurfaces.add(deferrableSurface);
            this.mCaptureConfigBuilder.addSurface(deferrableSurface);
        }

        public void addTag(@NonNull String str, @NonNull Integer num) {
            this.mCaptureConfigBuilder.addTag(str, num);
        }

        @NonNull
        public SessionConfig build() {
            return new SessionConfig(new ArrayList(this.mSurfaces), this.mDeviceStateCallbacks, this.mSessionStateCallbacks, this.mSingleCameraCaptureCallbacks, this.mErrorListeners, this.mCaptureConfigBuilder.build());
        }

        public void clearSurfaces() {
            this.mSurfaces.clear();
            this.mCaptureConfigBuilder.clearSurfaces();
        }

        @NonNull
        public List<CameraCaptureCallback> getSingleCameraCaptureCallbacks() {
            return Collections.unmodifiableList(this.mSingleCameraCaptureCallbacks);
        }

        public void removeSurface(@NonNull DeferrableSurface deferrableSurface) {
            this.mSurfaces.remove(deferrableSurface);
            this.mCaptureConfigBuilder.removeSurface(deferrableSurface);
        }

        public void setImplementationOptions(@NonNull Config config) {
            this.mCaptureConfigBuilder.setImplementationOptions(config);
        }

        public void setTemplateType(int i2) {
            this.mCaptureConfigBuilder.setTemplateType(i2);
        }
    }

    public interface ErrorListener {
        void onError(@NonNull SessionConfig sessionConfig, @NonNull SessionError sessionError);
    }

    public interface OptionUnpacker {
        void unpack(@NonNull UseCaseConfig<?> useCaseConfig, @NonNull Builder builder);
    }

    public enum SessionError {
        SESSION_ERROR_SURFACE_NEEDS_RESET,
        SESSION_ERROR_UNKNOWN
    }

    public static final class ValidatingBuilder extends BaseBuilder {
        private static final String TAG = "ValidatingBuilder";
        private boolean mValid = true;
        private boolean mTemplateSet = false;

        public void add(@NonNull SessionConfig sessionConfig) {
            CaptureConfig repeatingCaptureConfig = sessionConfig.getRepeatingCaptureConfig();
            if (repeatingCaptureConfig.getTemplateType() != -1) {
                if (!this.mTemplateSet) {
                    this.mCaptureConfigBuilder.setTemplateType(repeatingCaptureConfig.getTemplateType());
                    this.mTemplateSet = true;
                } else if (this.mCaptureConfigBuilder.getTemplateType() != repeatingCaptureConfig.getTemplateType()) {
                    StringBuilder m586H = C1499a.m586H("Invalid configuration due to template type: ");
                    m586H.append(this.mCaptureConfigBuilder.getTemplateType());
                    m586H.append(" != ");
                    m586H.append(repeatingCaptureConfig.getTemplateType());
                    Logger.m123d(TAG, m586H.toString());
                    this.mValid = false;
                }
            }
            this.mCaptureConfigBuilder.addAllTags(sessionConfig.getRepeatingCaptureConfig().getTagBundle());
            this.mDeviceStateCallbacks.addAll(sessionConfig.getDeviceStateCallbacks());
            this.mSessionStateCallbacks.addAll(sessionConfig.getSessionStateCallbacks());
            this.mCaptureConfigBuilder.addAllCameraCaptureCallbacks(sessionConfig.getRepeatingCameraCaptureCallbacks());
            this.mSingleCameraCaptureCallbacks.addAll(sessionConfig.getSingleCameraCaptureCallbacks());
            this.mErrorListeners.addAll(sessionConfig.getErrorListeners());
            this.mSurfaces.addAll(sessionConfig.getSurfaces());
            this.mCaptureConfigBuilder.getSurfaces().addAll(repeatingCaptureConfig.getSurfaces());
            if (!this.mSurfaces.containsAll(this.mCaptureConfigBuilder.getSurfaces())) {
                Logger.m123d(TAG, "Invalid configuration due to capture request surfaces are not a subset of surfaces");
                this.mValid = false;
            }
            this.mCaptureConfigBuilder.addImplementationOptions(repeatingCaptureConfig.getImplementationOptions());
        }

        @NonNull
        public SessionConfig build() {
            if (this.mValid) {
                return new SessionConfig(new ArrayList(this.mSurfaces), this.mDeviceStateCallbacks, this.mSessionStateCallbacks, this.mSingleCameraCaptureCallbacks, this.mErrorListeners, this.mCaptureConfigBuilder.build());
            }
            throw new IllegalArgumentException("Unsupported session configuration combination");
        }

        public boolean isValid() {
            return this.mTemplateSet && this.mValid;
        }
    }

    public SessionConfig(List<DeferrableSurface> list, List<CameraDevice.StateCallback> list2, List<CameraCaptureSession.StateCallback> list3, List<CameraCaptureCallback> list4, List<ErrorListener> list5, CaptureConfig captureConfig) {
        this.mSurfaces = list;
        this.mDeviceStateCallbacks = Collections.unmodifiableList(list2);
        this.mSessionStateCallbacks = Collections.unmodifiableList(list3);
        this.mSingleCameraCaptureCallbacks = Collections.unmodifiableList(list4);
        this.mErrorListeners = Collections.unmodifiableList(list5);
        this.mRepeatingCaptureConfig = captureConfig;
    }

    @NonNull
    public static SessionConfig defaultEmptySessionConfig() {
        return new SessionConfig(new ArrayList(), new ArrayList(0), new ArrayList(0), new ArrayList(0), new ArrayList(0), new CaptureConfig.Builder().build());
    }

    @NonNull
    public List<CameraDevice.StateCallback> getDeviceStateCallbacks() {
        return this.mDeviceStateCallbacks;
    }

    @NonNull
    public List<ErrorListener> getErrorListeners() {
        return this.mErrorListeners;
    }

    @NonNull
    public Config getImplementationOptions() {
        return this.mRepeatingCaptureConfig.getImplementationOptions();
    }

    @NonNull
    public List<CameraCaptureCallback> getRepeatingCameraCaptureCallbacks() {
        return this.mRepeatingCaptureConfig.getCameraCaptureCallbacks();
    }

    @NonNull
    public CaptureConfig getRepeatingCaptureConfig() {
        return this.mRepeatingCaptureConfig;
    }

    @NonNull
    public List<CameraCaptureSession.StateCallback> getSessionStateCallbacks() {
        return this.mSessionStateCallbacks;
    }

    @NonNull
    public List<CameraCaptureCallback> getSingleCameraCaptureCallbacks() {
        return this.mSingleCameraCaptureCallbacks;
    }

    @NonNull
    public List<DeferrableSurface> getSurfaces() {
        return Collections.unmodifiableList(this.mSurfaces);
    }

    public int getTemplateType() {
        return this.mRepeatingCaptureConfig.getTemplateType();
    }
}
