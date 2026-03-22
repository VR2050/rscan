package androidx.camera.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Handler;
import android.os.Looper;
import android.view.Display;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.VisibleForTesting;
import androidx.annotation.experimental.UseExperimental;
import androidx.arch.core.util.Function;
import androidx.camera.core.Camera;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ExperimentalUseCaseGroup;
import androidx.camera.core.FocusMeteringAction;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageCapture;
import androidx.camera.core.Logger;
import androidx.camera.core.MeteringPointFactory;
import androidx.camera.core.Preview;
import androidx.camera.core.UseCaseGroup;
import androidx.camera.core.VideoCapture;
import androidx.camera.core.ViewPort;
import androidx.camera.core.ZoomState;
import androidx.camera.core.impl.utils.Threads;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.CameraController;
import androidx.camera.view.video.ExperimentalVideo;
import androidx.camera.view.video.OnVideoSavedCallback;
import androidx.camera.view.video.OutputFileOptions;
import androidx.camera.view.video.OutputFileResults;
import androidx.core.util.Preconditions;
import androidx.lifecycle.LiveData;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public abstract class CameraController {
    private static final float AE_SIZE = 0.25f;
    private static final float AF_SIZE = 0.16666667f;
    private static final String CAMERA_NOT_ATTACHED = "Use cases not attached to camera.";
    private static final String CAMERA_NOT_INITIALIZED = "Camera not initialized.";
    public static final int IMAGE_ANALYSIS = 2;
    public static final int IMAGE_CAPTURE = 1;
    private static final String IMAGE_CAPTURE_DISABLED = "ImageCapture disabled.";
    private static final String PREVIEW_VIEW_NOT_ATTACHED = "PreviewView not attached.";
    private static final String TAG = "CameraController";

    @ExperimentalVideo
    public static final int VIDEO_CAPTURE = 4;
    private static final String VIDEO_CAPTURE_DISABLED = "VideoCapture disabled.";

    @Nullable
    private ImageAnalysis.Analyzer mAnalysisAnalyzer;

    @Nullable
    private Executor mAnalysisExecutor;
    private final Context mAppContext;

    @Nullable
    public Camera mCamera;

    @Nullable
    public ProcessCameraProvider mCameraProvider;

    @Nullable
    private final DisplayRotationListener mDisplayRotationListener;

    @NonNull
    private ImageAnalysis mImageAnalysis;

    @NonNull
    public final ImageCapture mImageCapture;

    @NonNull
    private final InterfaceFutureC2413a<Void> mInitializationFuture;

    @NonNull
    public final Preview mPreview;

    @Nullable
    public Display mPreviewDisplay;

    @NonNull
    public final SensorRotationListener mSensorRotationListener;

    @Nullable
    public Preview.SurfaceProvider mSurfaceProvider;

    @NonNull
    public final VideoCapture mVideoCapture;

    @Nullable
    public ViewPort mViewPort;
    public CameraSelector mCameraSelector = CameraSelector.DEFAULT_BACK_CAMERA;
    private int mEnabledUseCases = 3;

    @NonNull
    public final AtomicBoolean mVideoIsRecording = new AtomicBoolean(false);
    private boolean mPinchToZoomEnabled = true;
    private boolean mTapToFocusEnabled = true;
    private final ForwardingLiveData<ZoomState> mZoomState = new ForwardingLiveData<>();
    private final ForwardingLiveData<Integer> mTorchState = new ForwardingLiveData<>();

    public class DisplayRotationListener implements DisplayManager.DisplayListener {
        public DisplayRotationListener() {
        }

        @Override // android.hardware.display.DisplayManager.DisplayListener
        public void onDisplayAdded(int i2) {
        }

        @Override // android.hardware.display.DisplayManager.DisplayListener
        @UseExperimental(markerClass = ExperimentalUseCaseGroup.class)
        @SuppressLint({"WrongConstant"})
        public void onDisplayChanged(int i2) {
            Display display = CameraController.this.mPreviewDisplay;
            if (display == null || display.getDisplayId() != i2) {
                return;
            }
            CameraController cameraController = CameraController.this;
            cameraController.mPreview.setTargetRotation(cameraController.mPreviewDisplay.getRotation());
        }

        @Override // android.hardware.display.DisplayManager.DisplayListener
        public void onDisplayRemoved(int i2) {
        }
    }

    public CameraController(@NonNull Context context) {
        Context applicationContext = context.getApplicationContext();
        this.mAppContext = applicationContext;
        this.mPreview = new Preview.Builder().build();
        this.mImageCapture = new ImageCapture.Builder().build();
        this.mImageAnalysis = new ImageAnalysis.Builder().build();
        this.mVideoCapture = new VideoCapture.Builder().build();
        this.mInitializationFuture = Futures.transform(ProcessCameraProvider.getInstance(applicationContext), new Function() { // from class: e.a.c.c
            @Override // androidx.arch.core.util.Function
            public final Object apply(Object obj) {
                CameraController cameraController = CameraController.this;
                cameraController.mCameraProvider = (ProcessCameraProvider) obj;
                cameraController.startCameraAndTrackStates();
                return null;
            }
        }, CameraXExecutors.mainThreadExecutor());
        this.mDisplayRotationListener = new DisplayRotationListener();
        this.mSensorRotationListener = new SensorRotationListener(applicationContext) { // from class: androidx.camera.view.CameraController.1
            @Override // androidx.camera.view.SensorRotationListener
            public void onRotationChanged(int i2) {
                CameraController.this.mImageCapture.setTargetRotation(i2);
                CameraController.this.mVideoCapture.setTargetRotation(i2);
            }
        };
    }

    private DisplayManager getDisplayManager() {
        return (DisplayManager) this.mAppContext.getSystemService("display");
    }

    private boolean isCameraAttached() {
        return this.mCamera != null;
    }

    private boolean isCameraInitialized() {
        return this.mCameraProvider != null;
    }

    private boolean isPreviewViewAttached() {
        return (this.mSurfaceProvider == null || this.mViewPort == null || this.mPreviewDisplay == null) ? false : true;
    }

    private boolean isUseCaseEnabled(int i2) {
        return (i2 & this.mEnabledUseCases) != 0;
    }

    @UseExperimental(markerClass = ExperimentalVideo.class)
    private boolean isVideoCaptureEnabledInternal() {
        return isVideoCaptureEnabled();
    }

    private float speedUpZoomBy2X(float f2) {
        return f2 > 1.0f ? C1499a.m627m(f2, 1.0f, 2.0f, 1.0f) : 1.0f - ((1.0f - f2) * 2.0f);
    }

    private void startListeningToRotationEvents() {
        getDisplayManager().registerDisplayListener(this.mDisplayRotationListener, new Handler(Looper.getMainLooper()));
        if (this.mSensorRotationListener.canDetectOrientation()) {
            this.mSensorRotationListener.enable();
        }
    }

    private void stopListeningToRotationEvents() {
        getDisplayManager().unregisterDisplayListener(this.mDisplayRotationListener);
        this.mSensorRotationListener.disable();
    }

    private void unbindImageAnalysisAndRecreate(int i2, int i3) {
        ImageAnalysis.Analyzer analyzer;
        if (isCameraInitialized()) {
            this.mCameraProvider.unbind(this.mImageAnalysis);
        }
        ImageAnalysis build = new ImageAnalysis.Builder().setBackpressureStrategy(i2).setImageQueueDepth(i3).build();
        this.mImageAnalysis = build;
        Executor executor = this.mAnalysisExecutor;
        if (executor == null || (analyzer = this.mAnalysisAnalyzer) == null) {
            return;
        }
        build.setAnalyzer(executor, analyzer);
    }

    /* renamed from: a */
    public /* synthetic */ void m145a(int i2) {
        this.mEnabledUseCases = i2;
    }

    @UseExperimental(markerClass = ExperimentalUseCaseGroup.class)
    @SuppressLint({"MissingPermission", "WrongConstant"})
    @MainThread
    public void attachPreviewSurface(@NonNull Preview.SurfaceProvider surfaceProvider, @NonNull ViewPort viewPort, @NonNull Display display) {
        Threads.checkMainThread();
        if (this.mSurfaceProvider != surfaceProvider) {
            this.mSurfaceProvider = surfaceProvider;
            this.mPreview.setSurfaceProvider(surfaceProvider);
        }
        this.mViewPort = viewPort;
        this.mPreviewDisplay = display;
        startListeningToRotationEvents();
        startCameraAndTrackStates();
    }

    @MainThread
    public void clearImageAnalysisAnalyzer() {
        Threads.checkMainThread();
        this.mAnalysisExecutor = null;
        this.mAnalysisAnalyzer = null;
        this.mImageAnalysis.clearAnalyzer();
    }

    @MainThread
    public void clearPreviewSurface() {
        Threads.checkMainThread();
        ProcessCameraProvider processCameraProvider = this.mCameraProvider;
        if (processCameraProvider != null) {
            processCameraProvider.unbindAll();
        }
        this.mPreview.setSurfaceProvider(null);
        this.mCamera = null;
        this.mSurfaceProvider = null;
        this.mViewPort = null;
        this.mPreviewDisplay = null;
        stopListeningToRotationEvents();
    }

    @Nullable
    @UseExperimental(markerClass = ExperimentalUseCaseGroup.class)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public UseCaseGroup createUseCaseGroup() {
        if (!isCameraInitialized()) {
            Logger.m123d(TAG, CAMERA_NOT_INITIALIZED);
            return null;
        }
        if (!isPreviewViewAttached()) {
            Logger.m123d(TAG, PREVIEW_VIEW_NOT_ATTACHED);
            return null;
        }
        UseCaseGroup.Builder addUseCase = new UseCaseGroup.Builder().addUseCase(this.mPreview);
        if (isImageCaptureEnabled()) {
            addUseCase.addUseCase(this.mImageCapture);
        } else {
            this.mCameraProvider.unbind(this.mImageCapture);
        }
        if (isImageAnalysisEnabled()) {
            addUseCase.addUseCase(this.mImageAnalysis);
        } else {
            this.mCameraProvider.unbind(this.mImageAnalysis);
        }
        if (isVideoCaptureEnabledInternal()) {
            addUseCase.addUseCase(this.mVideoCapture);
        } else {
            this.mCameraProvider.unbind(this.mVideoCapture);
        }
        addUseCase.setViewPort(this.mViewPort);
        return addUseCase.build();
    }

    @NonNull
    @MainThread
    public InterfaceFutureC2413a<Void> enableTorch(boolean z) {
        Threads.checkMainThread();
        if (isCameraAttached()) {
            return this.mCamera.getCameraControl().enableTorch(z);
        }
        Logger.m129w(TAG, CAMERA_NOT_ATTACHED);
        return Futures.immediateFuture(null);
    }

    @NonNull
    @MainThread
    public CameraSelector getCameraSelector() {
        Threads.checkMainThread();
        return this.mCameraSelector;
    }

    @MainThread
    public int getImageAnalysisBackpressureStrategy() {
        Threads.checkMainThread();
        return this.mImageAnalysis.getBackpressureStrategy();
    }

    @MainThread
    public int getImageAnalysisImageQueueDepth() {
        Threads.checkMainThread();
        return this.mImageAnalysis.getImageQueueDepth();
    }

    @MainThread
    public int getImageCaptureFlashMode() {
        Threads.checkMainThread();
        return this.mImageCapture.getFlashMode();
    }

    @NonNull
    public InterfaceFutureC2413a<Void> getInitializationFuture() {
        return this.mInitializationFuture;
    }

    @NonNull
    @MainThread
    public LiveData<Integer> getTorchState() {
        Threads.checkMainThread();
        return this.mTorchState;
    }

    @NonNull
    @MainThread
    public LiveData<ZoomState> getZoomState() {
        Threads.checkMainThread();
        return this.mZoomState;
    }

    @MainThread
    public boolean isImageAnalysisEnabled() {
        Threads.checkMainThread();
        return isUseCaseEnabled(2);
    }

    @MainThread
    public boolean isImageCaptureEnabled() {
        Threads.checkMainThread();
        return isUseCaseEnabled(1);
    }

    @MainThread
    public boolean isPinchToZoomEnabled() {
        Threads.checkMainThread();
        return this.mPinchToZoomEnabled;
    }

    @ExperimentalVideo
    @MainThread
    public boolean isRecording() {
        Threads.checkMainThread();
        return this.mVideoIsRecording.get();
    }

    @MainThread
    public boolean isTapToFocusEnabled() {
        Threads.checkMainThread();
        return this.mTapToFocusEnabled;
    }

    @ExperimentalVideo
    @MainThread
    public boolean isVideoCaptureEnabled() {
        Threads.checkMainThread();
        return isUseCaseEnabled(4);
    }

    public void onPinchToZoom(float f2) {
        if (!isCameraAttached()) {
            Logger.m129w(TAG, CAMERA_NOT_ATTACHED);
            return;
        }
        if (!this.mPinchToZoomEnabled) {
            Logger.m123d(TAG, "Pinch to zoom disabled.");
            return;
        }
        Logger.m123d(TAG, "Pinch to zoom with scale: " + f2);
        ZoomState value = getZoomState().getValue();
        if (value == null) {
            return;
        }
        setZoomRatio(Math.min(Math.max(value.getZoomRatio() * speedUpZoomBy2X(f2), value.getMinZoomRatio()), value.getMaxZoomRatio()));
    }

    public void onTapToFocus(MeteringPointFactory meteringPointFactory, float f2, float f3) {
        if (!isCameraAttached()) {
            Logger.m129w(TAG, CAMERA_NOT_ATTACHED);
            return;
        }
        if (!this.mTapToFocusEnabled) {
            Logger.m123d(TAG, "Tap to focus disabled. ");
            return;
        }
        Logger.m123d(TAG, "Tap to focus: " + f2 + ", " + f3);
        this.mCamera.getCameraControl().startFocusAndMetering(new FocusMeteringAction.Builder(meteringPointFactory.createPoint(f2, f3, AF_SIZE), 1).addPoint(meteringPointFactory.createPoint(f2, f3, 0.25f), 2).build());
    }

    @MainThread
    public void setCameraSelector(@NonNull CameraSelector cameraSelector) {
        ProcessCameraProvider processCameraProvider;
        Threads.checkMainThread();
        if (this.mCameraSelector == cameraSelector || (processCameraProvider = this.mCameraProvider) == null) {
            return;
        }
        processCameraProvider.unbindAll();
        final CameraSelector cameraSelector2 = this.mCameraSelector;
        this.mCameraSelector = cameraSelector;
        startCameraAndTrackStates(new Runnable() { // from class: e.a.c.d
            @Override // java.lang.Runnable
            public final void run() {
                CameraController.this.mCameraSelector = cameraSelector2;
            }
        });
    }

    @UseExperimental(markerClass = ExperimentalVideo.class)
    @MainThread
    public void setEnabledUseCases(int i2) {
        Threads.checkMainThread();
        final int i3 = this.mEnabledUseCases;
        if (i2 == i3) {
            return;
        }
        this.mEnabledUseCases = i2;
        if (!isVideoCaptureEnabled()) {
            stopRecording();
        }
        startCameraAndTrackStates(new Runnable() { // from class: e.a.c.b
            @Override // java.lang.Runnable
            public final void run() {
                CameraController.this.m145a(i3);
            }
        });
    }

    @MainThread
    public void setImageAnalysisAnalyzer(@NonNull Executor executor, @NonNull ImageAnalysis.Analyzer analyzer) {
        Threads.checkMainThread();
        if (this.mAnalysisAnalyzer == analyzer && this.mAnalysisExecutor == executor) {
            return;
        }
        this.mAnalysisExecutor = executor;
        this.mAnalysisAnalyzer = analyzer;
        this.mImageAnalysis.setAnalyzer(executor, analyzer);
    }

    @MainThread
    public void setImageAnalysisBackpressureStrategy(int i2) {
        Threads.checkMainThread();
        if (this.mImageAnalysis.getBackpressureStrategy() == i2) {
            return;
        }
        unbindImageAnalysisAndRecreate(i2, this.mImageAnalysis.getImageQueueDepth());
        startCameraAndTrackStates();
    }

    @MainThread
    public void setImageAnalysisImageQueueDepth(int i2) {
        Threads.checkMainThread();
        if (this.mImageAnalysis.getImageQueueDepth() == i2) {
            return;
        }
        unbindImageAnalysisAndRecreate(this.mImageAnalysis.getBackpressureStrategy(), i2);
        startCameraAndTrackStates();
    }

    @MainThread
    public void setImageCaptureFlashMode(int i2) {
        Threads.checkMainThread();
        this.mImageCapture.setFlashMode(i2);
    }

    @NonNull
    @MainThread
    public InterfaceFutureC2413a<Void> setLinearZoom(float f2) {
        Threads.checkMainThread();
        if (isCameraAttached()) {
            return this.mCamera.getCameraControl().setLinearZoom(f2);
        }
        Logger.m129w(TAG, CAMERA_NOT_ATTACHED);
        return Futures.immediateFuture(null);
    }

    @MainThread
    public void setPinchToZoomEnabled(boolean z) {
        Threads.checkMainThread();
        this.mPinchToZoomEnabled = z;
    }

    @MainThread
    public void setTapToFocusEnabled(boolean z) {
        Threads.checkMainThread();
        this.mTapToFocusEnabled = z;
    }

    @NonNull
    @MainThread
    public InterfaceFutureC2413a<Void> setZoomRatio(float f2) {
        Threads.checkMainThread();
        if (isCameraAttached()) {
            return this.mCamera.getCameraControl().setZoomRatio(f2);
        }
        Logger.m129w(TAG, CAMERA_NOT_ATTACHED);
        return Futures.immediateFuture(null);
    }

    @Nullable
    public abstract Camera startCamera();

    public void startCameraAndTrackStates() {
        startCameraAndTrackStates(null);
    }

    @ExperimentalVideo
    @MainThread
    public void startRecording(@NonNull OutputFileOptions outputFileOptions, @NonNull Executor executor, @NonNull final OnVideoSavedCallback onVideoSavedCallback) {
        Threads.checkMainThread();
        Preconditions.checkState(isCameraInitialized(), CAMERA_NOT_INITIALIZED);
        Preconditions.checkState(isVideoCaptureEnabled(), VIDEO_CAPTURE_DISABLED);
        this.mVideoCapture.startRecording(outputFileOptions.toVideoCaptureOutputFileOptions(), executor, new VideoCapture.OnVideoSavedCallback() { // from class: androidx.camera.view.CameraController.2
            @Override // androidx.camera.core.VideoCapture.OnVideoSavedCallback
            public void onError(int i2, @NonNull String str, @Nullable Throwable th) {
                CameraController.this.mVideoIsRecording.set(false);
                onVideoSavedCallback.onError(i2, str, th);
            }

            @Override // androidx.camera.core.VideoCapture.OnVideoSavedCallback
            public void onVideoSaved(@NonNull VideoCapture.OutputFileResults outputFileResults) {
                CameraController.this.mVideoIsRecording.set(false);
                onVideoSavedCallback.onVideoSaved(OutputFileResults.create(outputFileResults.getSavedUri()));
            }
        });
        this.mVideoIsRecording.set(true);
    }

    @ExperimentalVideo
    @MainThread
    public void stopRecording() {
        Threads.checkMainThread();
        if (this.mVideoIsRecording.get()) {
            this.mVideoCapture.stopRecording();
        }
    }

    @MainThread
    public void takePicture(@NonNull ImageCapture.OutputFileOptions outputFileOptions, @NonNull Executor executor, @NonNull ImageCapture.OnImageSavedCallback onImageSavedCallback) {
        Threads.checkMainThread();
        Preconditions.checkState(isCameraInitialized(), CAMERA_NOT_INITIALIZED);
        Preconditions.checkState(isImageCaptureEnabled(), IMAGE_CAPTURE_DISABLED);
        updateMirroringFlagInOutputFileOptions(outputFileOptions);
        this.mImageCapture.takePicture(outputFileOptions, executor, onImageSavedCallback);
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    @VisibleForTesting
    public void updateMirroringFlagInOutputFileOptions(@NonNull ImageCapture.OutputFileOptions outputFileOptions) {
        if (this.mCameraSelector.getLensFacing() == null || outputFileOptions.getMetadata().isReversedHorizontalSet()) {
            return;
        }
        outputFileOptions.getMetadata().setReversedHorizontal(this.mCameraSelector.getLensFacing().intValue() == 0);
    }

    public void startCameraAndTrackStates(@Nullable Runnable runnable) {
        try {
            this.mCamera = startCamera();
            if (!isCameraAttached()) {
                Logger.m123d(TAG, CAMERA_NOT_ATTACHED);
            } else {
                this.mZoomState.setSource(this.mCamera.getCameraInfo().getZoomState());
                this.mTorchState.setSource(this.mCamera.getCameraInfo().getTorchState());
            }
        } catch (IllegalArgumentException e2) {
            if (runnable != null) {
                runnable.run();
            }
            throw new IllegalStateException("The selected camera does not support the enabled use cases. Please disable use case and/or select a different camera. e.g. #setVideoCaptureEnabled(false)", e2);
        }
    }

    @MainThread
    public void takePicture(@NonNull Executor executor, @NonNull ImageCapture.OnImageCapturedCallback onImageCapturedCallback) {
        Threads.checkMainThread();
        Preconditions.checkState(isCameraInitialized(), CAMERA_NOT_INITIALIZED);
        Preconditions.checkState(isImageCaptureEnabled(), IMAGE_CAPTURE_DISABLED);
        this.mImageCapture.takePicture(executor, onImageCapturedCallback);
    }
}
