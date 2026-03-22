package androidx.camera.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Rational;
import android.util.Size;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresPermission;
import androidx.annotation.experimental.UseExperimental;
import androidx.camera.core.Camera;
import androidx.camera.core.CameraInfoUnavailableException;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageCapture;
import androidx.camera.core.Logger;
import androidx.camera.core.Preview;
import androidx.camera.core.UseCase;
import androidx.camera.core.VideoCapture;
import androidx.camera.core.impl.LensFacingConverter;
import androidx.camera.core.impl.utils.CameraOrientationUtil;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.CameraView;
import androidx.camera.view.video.ExperimentalVideo;
import androidx.core.util.Preconditions;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.OnLifecycleEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class CameraXModule {
    public static final String TAG = "CameraXModule";
    private static final float UNITY_ZOOM_SCALE = 1.0f;
    private static final float ZOOM_NOT_SUPPORTED = 1.0f;

    @Nullable
    public Camera mCamera;

    @Nullable
    public ProcessCameraProvider mCameraProvider;
    private final CameraView mCameraView;

    @Nullable
    public LifecycleOwner mCurrentLifecycle;

    @Nullable
    private ImageCapture mImageCapture;
    private final ImageCapture.Builder mImageCaptureBuilder;

    @Nullable
    private LifecycleOwner mNewLifecycle;

    @Nullable
    public Preview mPreview;
    private final Preview.Builder mPreviewBuilder;

    @Nullable
    private VideoCapture mVideoCapture;
    private final VideoCapture.Builder mVideoCaptureBuilder;
    private static final Rational ASPECT_RATIO_16_9 = new Rational(16, 9);
    private static final Rational ASPECT_RATIO_4_3 = new Rational(4, 3);
    private static final Rational ASPECT_RATIO_9_16 = new Rational(9, 16);
    private static final Rational ASPECT_RATIO_3_4 = new Rational(3, 4);
    public final AtomicBoolean mVideoIsRecording = new AtomicBoolean(false);
    private CameraView.CaptureMode mCaptureMode = CameraView.CaptureMode.IMAGE;
    private long mMaxVideoDuration = -1;
    private long mMaxVideoSize = -1;
    private int mFlash = 2;
    private final LifecycleObserver mCurrentLifecycleObserver = new LifecycleObserver() { // from class: androidx.camera.view.CameraXModule.1
        @OnLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        public void onDestroy(LifecycleOwner lifecycleOwner) {
            CameraXModule cameraXModule = CameraXModule.this;
            if (lifecycleOwner == cameraXModule.mCurrentLifecycle) {
                cameraXModule.clearCurrentLifecycle();
            }
        }
    };

    @Nullable
    public Integer mCameraLensFacing = 1;

    public CameraXModule(CameraView cameraView) {
        this.mCameraView = cameraView;
        Futures.addCallback(ProcessCameraProvider.getInstance(cameraView.getContext()), new FutureCallback<ProcessCameraProvider>() { // from class: androidx.camera.view.CameraXModule.2
            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onFailure(Throwable th) {
                throw new RuntimeException("CameraX failed to initialize.", th);
            }

            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            @SuppressLint({"MissingPermission"})
            public void onSuccess(@Nullable ProcessCameraProvider processCameraProvider) {
                Preconditions.checkNotNull(processCameraProvider);
                CameraXModule cameraXModule = CameraXModule.this;
                cameraXModule.mCameraProvider = processCameraProvider;
                LifecycleOwner lifecycleOwner = cameraXModule.mCurrentLifecycle;
                if (lifecycleOwner != null) {
                    cameraXModule.bindToLifecycle(lifecycleOwner);
                }
            }
        }, CameraXExecutors.mainThreadExecutor());
        this.mPreviewBuilder = new Preview.Builder().setTargetName("Preview");
        this.mImageCaptureBuilder = new ImageCapture.Builder().setTargetName("ImageCapture");
        this.mVideoCaptureBuilder = new VideoCapture.Builder().setTargetName("VideoCapture");
    }

    @RequiresPermission("android.permission.CAMERA")
    private Set<Integer> getAvailableCameraLensFacing() {
        LinkedHashSet linkedHashSet = new LinkedHashSet(Arrays.asList(LensFacingConverter.values()));
        if (this.mCurrentLifecycle != null) {
            if (!hasCameraWithLensFacing(1)) {
                linkedHashSet.remove(1);
            }
            if (!hasCameraWithLensFacing(0)) {
                linkedHashSet.remove(0);
            }
        }
        return linkedHashSet;
    }

    private int getMeasuredHeight() {
        return this.mCameraView.getMeasuredHeight();
    }

    private int getMeasuredWidth() {
        return this.mCameraView.getMeasuredWidth();
    }

    @SuppressLint({"MissingPermission"})
    private void rebindToLifecycle() {
        LifecycleOwner lifecycleOwner = this.mCurrentLifecycle;
        if (lifecycleOwner != null) {
            bindToLifecycle(lifecycleOwner);
        }
    }

    private void updateViewInfo() {
        ImageCapture imageCapture = this.mImageCapture;
        if (imageCapture != null) {
            imageCapture.setCropAspectRatio(new Rational(getWidth(), getHeight()));
            this.mImageCapture.setTargetRotation(getDisplaySurfaceRotation());
        }
        VideoCapture videoCapture = this.mVideoCapture;
        if (videoCapture != null) {
            videoCapture.setTargetRotation(getDisplaySurfaceRotation());
        }
    }

    @RequiresPermission("android.permission.CAMERA")
    public void bindToLifecycle(LifecycleOwner lifecycleOwner) {
        this.mNewLifecycle = lifecycleOwner;
        if (getMeasuredWidth() <= 0 || getMeasuredHeight() <= 0) {
            return;
        }
        bindToLifecycleAfterViewMeasured();
    }

    @UseExperimental(markerClass = ExperimentalVideo.class)
    @RequiresPermission("android.permission.CAMERA")
    public void bindToLifecycleAfterViewMeasured() {
        Rational rational;
        if (this.mNewLifecycle == null) {
            return;
        }
        clearCurrentLifecycle();
        if (this.mNewLifecycle.getLifecycle().getCurrentState() == Lifecycle.State.DESTROYED) {
            this.mNewLifecycle = null;
            return;
        }
        this.mCurrentLifecycle = this.mNewLifecycle;
        this.mNewLifecycle = null;
        if (this.mCameraProvider == null) {
            return;
        }
        Set<Integer> availableCameraLensFacing = getAvailableCameraLensFacing();
        if (availableCameraLensFacing.isEmpty()) {
            Logger.m129w(TAG, "Unable to bindToLifeCycle since no cameras available");
            this.mCameraLensFacing = null;
        }
        Integer num = this.mCameraLensFacing;
        if (num != null && !availableCameraLensFacing.contains(num)) {
            StringBuilder m586H = C1499a.m586H("Camera does not exist with direction ");
            m586H.append(this.mCameraLensFacing);
            Logger.m129w(TAG, m586H.toString());
            this.mCameraLensFacing = availableCameraLensFacing.iterator().next();
            StringBuilder m586H2 = C1499a.m586H("Defaulting to primary camera with direction ");
            m586H2.append(this.mCameraLensFacing);
            Logger.m129w(TAG, m586H2.toString());
        }
        if (this.mCameraLensFacing == null) {
            return;
        }
        boolean z = getDisplayRotationDegrees() == 0 || getDisplayRotationDegrees() == 180;
        CameraView.CaptureMode captureMode = getCaptureMode();
        CameraView.CaptureMode captureMode2 = CameraView.CaptureMode.IMAGE;
        if (captureMode == captureMode2) {
            rational = z ? ASPECT_RATIO_3_4 : ASPECT_RATIO_4_3;
        } else {
            this.mImageCaptureBuilder.setTargetAspectRatio(1);
            this.mVideoCaptureBuilder.setTargetAspectRatio(1);
            rational = z ? ASPECT_RATIO_9_16 : ASPECT_RATIO_16_9;
        }
        this.mImageCaptureBuilder.setTargetRotation(getDisplaySurfaceRotation());
        this.mImageCapture = this.mImageCaptureBuilder.build();
        this.mVideoCaptureBuilder.setTargetRotation(getDisplaySurfaceRotation());
        this.mVideoCapture = this.mVideoCaptureBuilder.build();
        this.mPreviewBuilder.setTargetResolution(new Size(getMeasuredWidth(), (int) (getMeasuredWidth() / rational.floatValue())));
        Preview build = this.mPreviewBuilder.build();
        this.mPreview = build;
        build.setSurfaceProvider(this.mCameraView.getPreviewView().getSurfaceProvider());
        CameraSelector build2 = new CameraSelector.Builder().requireLensFacing(this.mCameraLensFacing.intValue()).build();
        if (getCaptureMode() == captureMode2) {
            this.mCamera = this.mCameraProvider.bindToLifecycle(this.mCurrentLifecycle, build2, this.mImageCapture, this.mPreview);
        } else if (getCaptureMode() == CameraView.CaptureMode.VIDEO) {
            this.mCamera = this.mCameraProvider.bindToLifecycle(this.mCurrentLifecycle, build2, this.mVideoCapture, this.mPreview);
        } else {
            this.mCamera = this.mCameraProvider.bindToLifecycle(this.mCurrentLifecycle, build2, this.mImageCapture, this.mVideoCapture, this.mPreview);
        }
        setZoomRatio(1.0f);
        this.mCurrentLifecycle.getLifecycle().addObserver(this.mCurrentLifecycleObserver);
        setFlash(getFlash());
    }

    public void clearCurrentLifecycle() {
        if (this.mCurrentLifecycle != null && this.mCameraProvider != null) {
            ArrayList arrayList = new ArrayList();
            ImageCapture imageCapture = this.mImageCapture;
            if (imageCapture != null && this.mCameraProvider.isBound(imageCapture)) {
                arrayList.add(this.mImageCapture);
            }
            VideoCapture videoCapture = this.mVideoCapture;
            if (videoCapture != null && this.mCameraProvider.isBound(videoCapture)) {
                arrayList.add(this.mVideoCapture);
            }
            Preview preview = this.mPreview;
            if (preview != null && this.mCameraProvider.isBound(preview)) {
                arrayList.add(this.mPreview);
            }
            if (!arrayList.isEmpty()) {
                this.mCameraProvider.unbind((UseCase[]) arrayList.toArray(new UseCase[0]));
            }
            Preview preview2 = this.mPreview;
            if (preview2 != null) {
                preview2.setSurfaceProvider(null);
            }
        }
        this.mCamera = null;
        this.mCurrentLifecycle = null;
    }

    public void close() {
        throw new UnsupportedOperationException("Explicit open/close of camera not yet supported. Use bindtoLifecycle() instead.");
    }

    public void enableTorch(boolean z) {
        Camera camera = this.mCamera;
        if (camera == null) {
            return;
        }
        Futures.addCallback(camera.getCameraControl().enableTorch(z), new FutureCallback<Void>() { // from class: androidx.camera.view.CameraXModule.5
            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onFailure(Throwable th) {
                throw new RuntimeException(th);
            }

            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onSuccess(@Nullable Void r1) {
            }
        }, CameraXExecutors.directExecutor());
    }

    @Nullable
    public Camera getCamera() {
        return this.mCamera;
    }

    @NonNull
    public CameraView.CaptureMode getCaptureMode() {
        return this.mCaptureMode;
    }

    public Context getContext() {
        return this.mCameraView.getContext();
    }

    public int getDisplayRotationDegrees() {
        return CameraOrientationUtil.surfaceRotationToDegrees(getDisplaySurfaceRotation());
    }

    public int getDisplaySurfaceRotation() {
        return this.mCameraView.getDisplaySurfaceRotation();
    }

    public int getFlash() {
        return this.mFlash;
    }

    public int getHeight() {
        return this.mCameraView.getHeight();
    }

    @Nullable
    public Integer getLensFacing() {
        return this.mCameraLensFacing;
    }

    public long getMaxVideoDuration() {
        return this.mMaxVideoDuration;
    }

    public long getMaxVideoSize() {
        return this.mMaxVideoSize;
    }

    public float getMaxZoomRatio() {
        Camera camera = this.mCamera;
        if (camera != null) {
            return camera.getCameraInfo().getZoomState().getValue().getMaxZoomRatio();
        }
        return 1.0f;
    }

    public float getMinZoomRatio() {
        Camera camera = this.mCamera;
        if (camera != null) {
            return camera.getCameraInfo().getZoomState().getValue().getMinZoomRatio();
        }
        return 1.0f;
    }

    public int getRelativeCameraOrientation(boolean z) {
        Camera camera = this.mCamera;
        if (camera == null) {
            return 0;
        }
        int sensorRotationDegrees = camera.getCameraInfo().getSensorRotationDegrees(getDisplaySurfaceRotation());
        return z ? (360 - sensorRotationDegrees) % 360 : sensorRotationDegrees;
    }

    public int getWidth() {
        return this.mCameraView.getWidth();
    }

    public float getZoomRatio() {
        Camera camera = this.mCamera;
        if (camera != null) {
            return camera.getCameraInfo().getZoomState().getValue().getZoomRatio();
        }
        return 1.0f;
    }

    @RequiresPermission("android.permission.CAMERA")
    public boolean hasCameraWithLensFacing(int i2) {
        ProcessCameraProvider processCameraProvider = this.mCameraProvider;
        if (processCameraProvider == null) {
            return false;
        }
        try {
            return processCameraProvider.hasCamera(new CameraSelector.Builder().requireLensFacing(i2).build());
        } catch (CameraInfoUnavailableException unused) {
            return false;
        }
    }

    public void invalidateView() {
        updateViewInfo();
    }

    public boolean isBoundToLifecycle() {
        return this.mCamera != null;
    }

    public boolean isPaused() {
        return false;
    }

    public boolean isRecording() {
        return this.mVideoIsRecording.get();
    }

    public boolean isTorchOn() {
        Camera camera = this.mCamera;
        return camera != null && camera.getCameraInfo().getTorchState().getValue().intValue() == 1;
    }

    public boolean isZoomSupported() {
        return getMaxZoomRatio() != 1.0f;
    }

    public void open() {
        throw new UnsupportedOperationException("Explicit open/close of camera not yet supported. Use bindtoLifecycle() instead.");
    }

    @SuppressLint({"MissingPermission"})
    public void setCameraLensFacing(@Nullable Integer num) {
        if (Objects.equals(this.mCameraLensFacing, num)) {
            return;
        }
        this.mCameraLensFacing = num;
        LifecycleOwner lifecycleOwner = this.mCurrentLifecycle;
        if (lifecycleOwner != null) {
            bindToLifecycle(lifecycleOwner);
        }
    }

    public void setCaptureMode(@NonNull CameraView.CaptureMode captureMode) {
        this.mCaptureMode = captureMode;
        rebindToLifecycle();
    }

    public void setFlash(int i2) {
        this.mFlash = i2;
        ImageCapture imageCapture = this.mImageCapture;
        if (imageCapture == null) {
            return;
        }
        imageCapture.setFlashMode(i2);
    }

    public void setMaxVideoDuration(long j2) {
        this.mMaxVideoDuration = j2;
    }

    public void setMaxVideoSize(long j2) {
        this.mMaxVideoSize = j2;
    }

    public void setZoomRatio(float f2) {
        Camera camera = this.mCamera;
        if (camera != null) {
            Futures.addCallback(camera.getCameraControl().setZoomRatio(f2), new FutureCallback<Void>() { // from class: androidx.camera.view.CameraXModule.4
                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onFailure(Throwable th) {
                    throw new RuntimeException(th);
                }

                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onSuccess(@Nullable Void r1) {
                }
            }, CameraXExecutors.directExecutor());
        } else {
            Logger.m125e(TAG, "Failed to set zoom ratio");
        }
    }

    public void startRecording(VideoCapture.OutputFileOptions outputFileOptions, Executor executor, final VideoCapture.OnVideoSavedCallback onVideoSavedCallback) {
        if (this.mVideoCapture == null) {
            return;
        }
        if (getCaptureMode() == CameraView.CaptureMode.IMAGE) {
            throw new IllegalStateException("Can not record video under IMAGE capture mode.");
        }
        if (onVideoSavedCallback == null) {
            throw new IllegalArgumentException("OnVideoSavedCallback should not be empty");
        }
        this.mVideoIsRecording.set(true);
        this.mVideoCapture.startRecording(outputFileOptions, executor, new VideoCapture.OnVideoSavedCallback() { // from class: androidx.camera.view.CameraXModule.3
            @Override // androidx.camera.core.VideoCapture.OnVideoSavedCallback
            public void onError(int i2, @NonNull String str, @Nullable Throwable th) {
                CameraXModule.this.mVideoIsRecording.set(false);
                Logger.m126e(CameraXModule.TAG, str, th);
                onVideoSavedCallback.onError(i2, str, th);
            }

            @Override // androidx.camera.core.VideoCapture.OnVideoSavedCallback
            public void onVideoSaved(@NonNull VideoCapture.OutputFileResults outputFileResults) {
                CameraXModule.this.mVideoIsRecording.set(false);
                onVideoSavedCallback.onVideoSaved(outputFileResults);
            }
        });
    }

    public void stopRecording() {
        VideoCapture videoCapture = this.mVideoCapture;
        if (videoCapture == null) {
            return;
        }
        videoCapture.stopRecording();
    }

    @UseExperimental(markerClass = ExperimentalVideo.class)
    public void takePicture(Executor executor, ImageCapture.OnImageCapturedCallback onImageCapturedCallback) {
        if (this.mImageCapture == null) {
            return;
        }
        if (getCaptureMode() == CameraView.CaptureMode.VIDEO) {
            throw new IllegalStateException("Can not take picture under VIDEO capture mode.");
        }
        if (onImageCapturedCallback == null) {
            throw new IllegalArgumentException("OnImageCapturedCallback should not be empty");
        }
        this.mImageCapture.takePicture(executor, onImageCapturedCallback);
    }

    public void toggleCamera() {
        Set<Integer> availableCameraLensFacing = getAvailableCameraLensFacing();
        if (availableCameraLensFacing.isEmpty()) {
            return;
        }
        Integer num = this.mCameraLensFacing;
        if (num == null) {
            setCameraLensFacing(availableCameraLensFacing.iterator().next());
            return;
        }
        if (num.intValue() == 1 && availableCameraLensFacing.contains(0)) {
            setCameraLensFacing(0);
        } else if (this.mCameraLensFacing.intValue() == 0 && availableCameraLensFacing.contains(1)) {
            setCameraLensFacing(1);
        }
    }

    @UseExperimental(markerClass = ExperimentalVideo.class)
    public void takePicture(@NonNull ImageCapture.OutputFileOptions outputFileOptions, @NonNull Executor executor, ImageCapture.OnImageSavedCallback onImageSavedCallback) {
        if (this.mImageCapture == null) {
            return;
        }
        if (getCaptureMode() == CameraView.CaptureMode.VIDEO) {
            throw new IllegalStateException("Can not take picture under VIDEO capture mode.");
        }
        if (onImageSavedCallback != null) {
            ImageCapture.Metadata metadata = outputFileOptions.getMetadata();
            Integer num = this.mCameraLensFacing;
            metadata.setReversedHorizontal(num != null && num.intValue() == 0);
            this.mImageCapture.takePicture(outputFileOptions, executor, onImageSavedCallback);
            return;
        }
        throw new IllegalArgumentException("OnImageSavedCallback should not be empty");
    }
}
