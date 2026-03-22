package androidx.camera.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.TypedArray;
import android.hardware.display.DisplayManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.Display;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.ViewConfiguration;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.RequiresPermission;
import androidx.annotation.RestrictTo;
import androidx.camera.core.Camera;
import androidx.camera.core.FocusMeteringAction;
import androidx.camera.core.FocusMeteringResult;
import androidx.camera.core.ImageCapture;
import androidx.camera.core.Logger;
import androidx.camera.core.MeteringPointFactory;
import androidx.camera.core.VideoCapture;
import androidx.camera.core.impl.LensFacingConverter;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.camera.view.PreviewView;
import androidx.camera.view.video.ExperimentalVideo;
import androidx.camera.view.video.OnVideoSavedCallback;
import androidx.camera.view.video.OutputFileOptions;
import androidx.camera.view.video.OutputFileResults;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.LiveData;
import java.io.File;
import java.util.concurrent.Executor;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class CameraView extends FrameLayout {
    private static final String EXTRA_CAMERA_DIRECTION = "camera_direction";
    private static final String EXTRA_CAPTURE_MODE = "captureMode";
    private static final String EXTRA_FLASH = "flash";
    private static final String EXTRA_MAX_VIDEO_DURATION = "max_video_duration";
    private static final String EXTRA_MAX_VIDEO_SIZE = "max_video_size";
    private static final String EXTRA_PINCH_TO_ZOOM_ENABLED = "pinch_to_zoom_enabled";
    private static final String EXTRA_SCALE_TYPE = "scale_type";
    private static final String EXTRA_SUPER = "super";
    private static final String EXTRA_ZOOM_RATIO = "zoom_ratio";
    private static final int FLASH_MODE_AUTO = 1;
    private static final int FLASH_MODE_OFF = 4;
    private static final int FLASH_MODE_ON = 2;
    public static final int INDEFINITE_VIDEO_DURATION = -1;
    public static final int INDEFINITE_VIDEO_SIZE = -1;
    private static final int LENS_FACING_BACK = 2;
    private static final int LENS_FACING_FRONT = 1;
    private static final int LENS_FACING_NONE = 0;
    public static final String TAG = CameraView.class.getSimpleName();
    public CameraXModule mCameraModule;
    private final DisplayManager.DisplayListener mDisplayListener;
    private long mDownEventTimestamp;
    private boolean mIsPinchToZoomEnabled;
    private PinchToZoomGestureDetector mPinchToZoomGestureDetector;
    private PreviewView mPreviewView;
    private MotionEvent mUpEvent;

    public enum CaptureMode {
        IMAGE(0),
        VIDEO(1),
        MIXED(2);

        private final int mId;

        CaptureMode(int i2) {
            this.mId = i2;
        }

        public static CaptureMode fromId(int i2) {
            CaptureMode[] values = values();
            for (int i3 = 0; i3 < 3; i3++) {
                CaptureMode captureMode = values[i3];
                if (captureMode.mId == i2) {
                    return captureMode;
                }
            }
            throw new IllegalArgumentException();
        }

        public int getId() {
            return this.mId;
        }
    }

    public class PinchToZoomGestureDetector extends ScaleGestureDetector implements ScaleGestureDetector.OnScaleGestureListener {
        public PinchToZoomGestureDetector(CameraView cameraView, Context context) {
            this(context, new C0207S());
        }

        @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
        public boolean onScale(ScaleGestureDetector scaleGestureDetector) {
            float scaleFactor = scaleGestureDetector.getScaleFactor();
            float zoomRatio = CameraView.this.getZoomRatio() * (scaleFactor > 1.0f ? C1499a.m627m(scaleFactor, 1.0f, 2.0f, 1.0f) : 1.0f - ((1.0f - scaleFactor) * 2.0f));
            CameraView cameraView = CameraView.this;
            CameraView.this.setZoomRatio(cameraView.rangeLimit(zoomRatio, cameraView.getMaxZoomRatio(), CameraView.this.getMinZoomRatio()));
            return true;
        }

        @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
        public boolean onScaleBegin(ScaleGestureDetector scaleGestureDetector) {
            return true;
        }

        @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
        public void onScaleEnd(ScaleGestureDetector scaleGestureDetector) {
        }

        public PinchToZoomGestureDetector(Context context, C0207S c0207s) {
            super(context, c0207s);
            c0207s.setRealGestureDetector(this);
        }
    }

    /* renamed from: androidx.camera.view.CameraView$S */
    public static class C0207S extends ScaleGestureDetector.SimpleOnScaleGestureListener {
        private ScaleGestureDetector.OnScaleGestureListener mListener;

        @Override // android.view.ScaleGestureDetector.SimpleOnScaleGestureListener, android.view.ScaleGestureDetector.OnScaleGestureListener
        public boolean onScale(ScaleGestureDetector scaleGestureDetector) {
            return this.mListener.onScale(scaleGestureDetector);
        }

        public void setRealGestureDetector(ScaleGestureDetector.OnScaleGestureListener onScaleGestureListener) {
            this.mListener = onScaleGestureListener;
        }
    }

    public CameraView(@NonNull Context context) {
        this(context, null);
    }

    private long delta() {
        return System.currentTimeMillis() - this.mDownEventTimestamp;
    }

    private long getMaxVideoSize() {
        return this.mCameraModule.getMaxVideoSize();
    }

    private void init(Context context, @Nullable AttributeSet attributeSet) {
        PreviewView previewView = new PreviewView(getContext());
        this.mPreviewView = previewView;
        addView(previewView, 0);
        this.mCameraModule = new CameraXModule(this);
        if (attributeSet != null) {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0218R.styleable.CameraView);
            setScaleType(PreviewView.ScaleType.fromId(obtainStyledAttributes.getInteger(C0218R.styleable.CameraView_scaleType, getScaleType().getId())));
            setPinchToZoomEnabled(obtainStyledAttributes.getBoolean(C0218R.styleable.CameraView_pinchToZoomEnabled, isPinchToZoomEnabled()));
            setCaptureMode(CaptureMode.fromId(obtainStyledAttributes.getInteger(C0218R.styleable.CameraView_captureMode, getCaptureMode().getId())));
            int i2 = obtainStyledAttributes.getInt(C0218R.styleable.CameraView_lensFacing, 2);
            if (i2 == 0) {
                setCameraLensFacing(null);
            } else if (i2 == 1) {
                setCameraLensFacing(0);
            } else if (i2 == 2) {
                setCameraLensFacing(1);
            }
            int i3 = obtainStyledAttributes.getInt(C0218R.styleable.CameraView_flash, 0);
            if (i3 == 1) {
                setFlash(0);
            } else if (i3 == 2) {
                setFlash(1);
            } else if (i3 == 4) {
                setFlash(2);
            }
            obtainStyledAttributes.recycle();
        }
        if (getBackground() == null) {
            setBackgroundColor(-15658735);
        }
        this.mPinchToZoomGestureDetector = new PinchToZoomGestureDetector(this, context);
    }

    private void setMaxVideoDuration(long j2) {
        this.mCameraModule.setMaxVideoDuration(j2);
    }

    private void setMaxVideoSize(long j2) {
        this.mCameraModule.setMaxVideoSize(j2);
    }

    @RequiresPermission("android.permission.CAMERA")
    public void bindToLifecycle(@NonNull LifecycleOwner lifecycleOwner) {
        this.mCameraModule.bindToLifecycle(lifecycleOwner);
    }

    public void enableTorch(boolean z) {
        this.mCameraModule.enableTorch(z);
    }

    @Nullable
    public Integer getCameraLensFacing() {
        return this.mCameraModule.getLensFacing();
    }

    @NonNull
    public CaptureMode getCaptureMode() {
        return this.mCameraModule.getCaptureMode();
    }

    public int getDisplaySurfaceRotation() {
        Display display = getDisplay();
        if (display == null) {
            return 0;
        }
        return display.getRotation();
    }

    public int getFlash() {
        return this.mCameraModule.getFlash();
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public long getMaxVideoDuration() {
        return this.mCameraModule.getMaxVideoDuration();
    }

    public float getMaxZoomRatio() {
        return this.mCameraModule.getMaxZoomRatio();
    }

    public float getMinZoomRatio() {
        return this.mCameraModule.getMinZoomRatio();
    }

    @NonNull
    public LiveData<PreviewView.StreamState> getPreviewStreamState() {
        return this.mPreviewView.getPreviewStreamState();
    }

    @NonNull
    public PreviewView getPreviewView() {
        return this.mPreviewView;
    }

    @NonNull
    public PreviewView.ScaleType getScaleType() {
        return this.mPreviewView.getScaleType();
    }

    public float getZoomRatio() {
        return this.mCameraModule.getZoomRatio();
    }

    @RequiresPermission("android.permission.CAMERA")
    public boolean hasCameraWithLensFacing(int i2) {
        return this.mCameraModule.hasCameraWithLensFacing(i2);
    }

    public boolean isPinchToZoomEnabled() {
        return this.mIsPinchToZoomEnabled;
    }

    @ExperimentalVideo
    public boolean isRecording() {
        return this.mCameraModule.isRecording();
    }

    public boolean isTorchOn() {
        return this.mCameraModule.isTorchOn();
    }

    public boolean isZoomSupported() {
        return this.mCameraModule.isZoomSupported();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        ((DisplayManager) getContext().getSystemService("display")).registerDisplayListener(this.mDisplayListener, new Handler(Looper.getMainLooper()));
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        ((DisplayManager) getContext().getSystemService("display")).unregisterDisplayListener(this.mDisplayListener);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    @SuppressLint({"MissingPermission"})
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        this.mCameraModule.bindToLifecycleAfterViewMeasured();
        this.mCameraModule.invalidateView();
        super.onLayout(z, i2, i3, i4, i5);
    }

    @Override // android.widget.FrameLayout, android.view.View
    @SuppressLint({"MissingPermission"})
    public void onMeasure(int i2, int i3) {
        if (getMeasuredWidth() > 0 && getMeasuredHeight() > 0) {
            this.mCameraModule.bindToLifecycleAfterViewMeasured();
        }
        super.onMeasure(i2, i3);
    }

    @Override // android.view.View
    public void onRestoreInstanceState(@Nullable Parcelable parcelable) {
        if (!(parcelable instanceof Bundle)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        Bundle bundle = (Bundle) parcelable;
        super.onRestoreInstanceState(bundle.getParcelable(EXTRA_SUPER));
        setScaleType(PreviewView.ScaleType.fromId(bundle.getInt(EXTRA_SCALE_TYPE)));
        setZoomRatio(bundle.getFloat(EXTRA_ZOOM_RATIO));
        setPinchToZoomEnabled(bundle.getBoolean(EXTRA_PINCH_TO_ZOOM_ENABLED));
        setFlash(FlashModeConverter.valueOf(bundle.getString(EXTRA_FLASH)));
        setMaxVideoDuration(bundle.getLong(EXTRA_MAX_VIDEO_DURATION));
        setMaxVideoSize(bundle.getLong(EXTRA_MAX_VIDEO_SIZE));
        String string = bundle.getString(EXTRA_CAMERA_DIRECTION);
        setCameraLensFacing(TextUtils.isEmpty(string) ? null : Integer.valueOf(LensFacingConverter.valueOf(string)));
        setCaptureMode(CaptureMode.fromId(bundle.getInt(EXTRA_CAPTURE_MODE)));
    }

    @Override // android.view.View
    @NonNull
    public Parcelable onSaveInstanceState() {
        Bundle bundle = new Bundle();
        bundle.putParcelable(EXTRA_SUPER, super.onSaveInstanceState());
        bundle.putInt(EXTRA_SCALE_TYPE, getScaleType().getId());
        bundle.putFloat(EXTRA_ZOOM_RATIO, getZoomRatio());
        bundle.putBoolean(EXTRA_PINCH_TO_ZOOM_ENABLED, isPinchToZoomEnabled());
        bundle.putString(EXTRA_FLASH, FlashModeConverter.nameOf(getFlash()));
        bundle.putLong(EXTRA_MAX_VIDEO_DURATION, getMaxVideoDuration());
        bundle.putLong(EXTRA_MAX_VIDEO_SIZE, getMaxVideoSize());
        if (getCameraLensFacing() != null) {
            bundle.putString(EXTRA_CAMERA_DIRECTION, LensFacingConverter.nameOf(getCameraLensFacing().intValue()));
        }
        bundle.putInt(EXTRA_CAPTURE_MODE, getCaptureMode().getId());
        return bundle;
    }

    @Override // android.view.View
    public boolean onTouchEvent(@NonNull MotionEvent motionEvent) {
        if (this.mCameraModule.isPaused()) {
            return false;
        }
        if (isPinchToZoomEnabled()) {
            this.mPinchToZoomGestureDetector.onTouchEvent(motionEvent);
        }
        if (motionEvent.getPointerCount() == 2 && isPinchToZoomEnabled() && isZoomSupported()) {
            return true;
        }
        int action = motionEvent.getAction();
        if (action == 0) {
            this.mDownEventTimestamp = System.currentTimeMillis();
        } else {
            if (action != 1) {
                return false;
            }
            if (delta() < ViewConfiguration.getLongPressTimeout() && this.mCameraModule.isBoundToLifecycle()) {
                this.mUpEvent = motionEvent;
                performClick();
            }
        }
        return true;
    }

    @Override // android.view.View
    public boolean performClick() {
        super.performClick();
        MotionEvent motionEvent = this.mUpEvent;
        float x = motionEvent != null ? motionEvent.getX() : getX() + (getWidth() / 2.0f);
        MotionEvent motionEvent2 = this.mUpEvent;
        float y = motionEvent2 != null ? motionEvent2.getY() : (getHeight() / 2.0f) + getY();
        this.mUpEvent = null;
        Camera camera = this.mCameraModule.getCamera();
        if (camera != null) {
            MeteringPointFactory meteringPointFactory = this.mPreviewView.getMeteringPointFactory();
            Futures.addCallback(camera.getCameraControl().startFocusAndMetering(new FocusMeteringAction.Builder(meteringPointFactory.createPoint(x, y, 0.16666667f), 1).addPoint(meteringPointFactory.createPoint(x, y, 0.25f), 2).build()), new FutureCallback<FocusMeteringResult>() { // from class: androidx.camera.view.CameraView.3
                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onFailure(Throwable th) {
                    throw new RuntimeException(th);
                }

                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onSuccess(@Nullable FocusMeteringResult focusMeteringResult) {
                }
            }, CameraXExecutors.directExecutor());
        } else {
            Logger.m123d(TAG, "cannot access camera");
        }
        return true;
    }

    public float rangeLimit(float f2, float f3, float f4) {
        return Math.min(Math.max(f2, f4), f3);
    }

    public void setCameraLensFacing(@Nullable Integer num) {
        this.mCameraModule.setCameraLensFacing(num);
    }

    public void setCaptureMode(@NonNull CaptureMode captureMode) {
        this.mCameraModule.setCaptureMode(captureMode);
    }

    public void setFlash(int i2) {
        this.mCameraModule.setFlash(i2);
    }

    public void setPinchToZoomEnabled(boolean z) {
        this.mIsPinchToZoomEnabled = z;
    }

    public void setScaleType(@NonNull PreviewView.ScaleType scaleType) {
        this.mPreviewView.setScaleType(scaleType);
    }

    public void setZoomRatio(float f2) {
        this.mCameraModule.setZoomRatio(f2);
    }

    @ExperimentalVideo
    public void startRecording(@NonNull File file, @NonNull Executor executor, @NonNull OnVideoSavedCallback onVideoSavedCallback) {
        startRecording(OutputFileOptions.builder(file).build(), executor, onVideoSavedCallback);
    }

    @ExperimentalVideo
    public void stopRecording() {
        this.mCameraModule.stopRecording();
    }

    public void takePicture(@NonNull Executor executor, @NonNull ImageCapture.OnImageCapturedCallback onImageCapturedCallback) {
        this.mCameraModule.takePicture(executor, onImageCapturedCallback);
    }

    public void toggleCamera() {
        this.mCameraModule.toggleCamera();
    }

    public CameraView(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    @NonNull
    public FrameLayout.LayoutParams generateDefaultLayoutParams() {
        return new FrameLayout.LayoutParams(-1, -1);
    }

    public void takePicture(@NonNull ImageCapture.OutputFileOptions outputFileOptions, @NonNull Executor executor, @NonNull ImageCapture.OnImageSavedCallback onImageSavedCallback) {
        this.mCameraModule.takePicture(outputFileOptions, executor, onImageSavedCallback);
    }

    public CameraView(@NonNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.mIsPinchToZoomEnabled = true;
        this.mDisplayListener = new DisplayManager.DisplayListener() { // from class: androidx.camera.view.CameraView.1
            @Override // android.hardware.display.DisplayManager.DisplayListener
            public void onDisplayAdded(int i3) {
            }

            @Override // android.hardware.display.DisplayManager.DisplayListener
            public void onDisplayChanged(int i3) {
                CameraView.this.mCameraModule.invalidateView();
            }

            @Override // android.hardware.display.DisplayManager.DisplayListener
            public void onDisplayRemoved(int i3) {
            }
        };
        init(context, attributeSet);
    }

    @ExperimentalVideo
    public void startRecording(@NonNull ParcelFileDescriptor parcelFileDescriptor, @NonNull Executor executor, @NonNull OnVideoSavedCallback onVideoSavedCallback) {
        startRecording(OutputFileOptions.builder(parcelFileDescriptor).build(), executor, onVideoSavedCallback);
    }

    @ExperimentalVideo
    public void startRecording(@NonNull OutputFileOptions outputFileOptions, @NonNull Executor executor, @NonNull final OnVideoSavedCallback onVideoSavedCallback) {
        this.mCameraModule.startRecording(outputFileOptions.toVideoCaptureOutputFileOptions(), executor, new VideoCapture.OnVideoSavedCallback() { // from class: androidx.camera.view.CameraView.2
            @Override // androidx.camera.core.VideoCapture.OnVideoSavedCallback
            public void onError(int i2, @NonNull String str, @Nullable Throwable th) {
                onVideoSavedCallback.onError(i2, str, th);
            }

            @Override // androidx.camera.core.VideoCapture.OnVideoSavedCallback
            public void onVideoSaved(@NonNull VideoCapture.OutputFileResults outputFileResults) {
                onVideoSavedCallback.onVideoSaved(OutputFileResults.create(outputFileResults.getSavedUri()));
            }
        });
    }

    @RequiresApi(21)
    public CameraView(@NonNull Context context, @Nullable AttributeSet attributeSet, int i2, int i3) {
        super(context, attributeSet, i2, i3);
        this.mIsPinchToZoomEnabled = true;
        this.mDisplayListener = new DisplayManager.DisplayListener() { // from class: androidx.camera.view.CameraView.1
            @Override // android.hardware.display.DisplayManager.DisplayListener
            public void onDisplayAdded(int i32) {
            }

            @Override // android.hardware.display.DisplayManager.DisplayListener
            public void onDisplayChanged(int i32) {
                CameraView.this.mCameraModule.invalidateView();
            }

            @Override // android.hardware.display.DisplayManager.DisplayListener
            public void onDisplayRemoved(int i32) {
            }
        };
        init(context, attributeSet);
    }
}
