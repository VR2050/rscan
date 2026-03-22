package androidx.camera.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Rational;
import android.util.Size;
import android.view.Display;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.FrameLayout;
import androidx.annotation.AnyThread;
import androidx.annotation.ColorRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.UiThread;
import androidx.annotation.VisibleForTesting;
import androidx.annotation.experimental.UseExperimental;
import androidx.camera.core.CameraInfo;
import androidx.camera.core.ExperimentalUseCaseGroup;
import androidx.camera.core.Logger;
import androidx.camera.core.MeteringPointFactory;
import androidx.camera.core.Preview;
import androidx.camera.core.SurfaceRequest;
import androidx.camera.core.ViewPort;
import androidx.camera.core.impl.CameraInfoInternal;
import androidx.camera.core.impl.CameraInternal;
import androidx.camera.core.impl.utils.Threads;
import androidx.camera.view.PreviewStreamStateObserver;
import androidx.camera.view.PreviewView;
import androidx.camera.view.PreviewViewImplementation;
import androidx.core.content.ContextCompat;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class PreviewView extends FrameLayout {

    @ColorRes
    public static final int DEFAULT_BACKGROUND_COLOR = 17170444;
    private static final ImplementationMode DEFAULT_IMPL_MODE = ImplementationMode.PERFORMANCE;
    private static final String TAG = "PreviewView";

    @Nullable
    public final AtomicReference<PreviewStreamStateObserver> mActiveStreamStateObserver;
    public CameraController mCameraController;

    @Nullable
    @VisibleForTesting
    public PreviewViewImplementation mImplementation;

    @NonNull
    public ImplementationMode mImplementationMode;
    private final View.OnLayoutChangeListener mOnLayoutChangeListener;

    @NonNull
    public final MutableLiveData<StreamState> mPreviewStreamStateLiveData;

    @NonNull
    public final PreviewTransformation mPreviewTransform;

    @NonNull
    public PreviewViewMeteringPointFactory mPreviewViewMeteringPointFactory;

    @NonNull
    private final ScaleGestureDetector mScaleGestureDetector;
    public final Preview.SurfaceProvider mSurfaceProvider;

    @Nullable
    private MotionEvent mTouchUpEvent;

    /* renamed from: androidx.camera.view.PreviewView$1 */
    public class C02161 implements Preview.SurfaceProvider {
        public C02161() {
        }

        @Override // androidx.camera.core.Preview.SurfaceProvider
        @UseExperimental(markerClass = ExperimentalUseCaseGroup.class)
        @AnyThread
        public void onSurfaceRequested(@NonNull final SurfaceRequest surfaceRequest) {
            PreviewViewImplementation surfaceViewImplementation;
            if (!Threads.isMainThread()) {
                ContextCompat.getMainExecutor(PreviewView.this.getContext()).execute(new Runnable() { // from class: e.a.c.j
                    @Override // java.lang.Runnable
                    public final void run() {
                        PreviewView.C02161 c02161 = PreviewView.C02161.this;
                        PreviewView.this.mSurfaceProvider.onSurfaceRequested(surfaceRequest);
                    }
                });
                return;
            }
            Logger.m123d(PreviewView.TAG, "Surface requested by Preview.");
            final CameraInternal camera = surfaceRequest.getCamera();
            surfaceRequest.setTransformationInfoListener(ContextCompat.getMainExecutor(PreviewView.this.getContext()), new SurfaceRequest.TransformationInfoListener() { // from class: e.a.c.i
                @Override // androidx.camera.core.SurfaceRequest.TransformationInfoListener
                public final void onTransformationInfoUpdate(SurfaceRequest.TransformationInfo transformationInfo) {
                    PreviewView.C02161 c02161 = PreviewView.C02161.this;
                    CameraInternal cameraInternal = camera;
                    SurfaceRequest surfaceRequest2 = surfaceRequest;
                    Objects.requireNonNull(c02161);
                    Logger.m123d("PreviewView", "Preview transformation info updated. " + transformationInfo);
                    PreviewView.this.mPreviewTransform.setTransformationInfo(transformationInfo, surfaceRequest2.getResolution(), cameraInternal.getCameraInfoInternal().getLensFacing().intValue() == 0);
                    PreviewView.this.redrawPreview();
                }
            });
            PreviewView previewView = PreviewView.this;
            if (previewView.shouldUseTextureView(surfaceRequest, previewView.mImplementationMode)) {
                PreviewView previewView2 = PreviewView.this;
                surfaceViewImplementation = new TextureViewImplementation(previewView2, previewView2.mPreviewTransform);
            } else {
                PreviewView previewView3 = PreviewView.this;
                surfaceViewImplementation = new SurfaceViewImplementation(previewView3, previewView3.mPreviewTransform);
            }
            previewView.mImplementation = surfaceViewImplementation;
            CameraInfoInternal cameraInfoInternal = (CameraInfoInternal) camera.getCameraInfo();
            PreviewView previewView4 = PreviewView.this;
            final PreviewStreamStateObserver previewStreamStateObserver = new PreviewStreamStateObserver(cameraInfoInternal, previewView4.mPreviewStreamStateLiveData, previewView4.mImplementation);
            PreviewView.this.mActiveStreamStateObserver.set(previewStreamStateObserver);
            camera.getCameraState().addObserver(ContextCompat.getMainExecutor(PreviewView.this.getContext()), previewStreamStateObserver);
            PreviewView.this.mImplementation.onSurfaceRequested(surfaceRequest, new PreviewViewImplementation.OnSurfaceNotInUseListener() { // from class: e.a.c.h
                @Override // androidx.camera.view.PreviewViewImplementation.OnSurfaceNotInUseListener
                public final void onSurfaceNotInUse() {
                    PreviewView.C02161 c02161 = PreviewView.C02161.this;
                    PreviewStreamStateObserver previewStreamStateObserver2 = previewStreamStateObserver;
                    CameraInternal cameraInternal = camera;
                    if (PreviewView.this.mActiveStreamStateObserver.compareAndSet(previewStreamStateObserver2, null)) {
                        previewStreamStateObserver2.updatePreviewStreamState(PreviewView.StreamState.IDLE);
                    }
                    previewStreamStateObserver2.clear();
                    cameraInternal.getCameraState().removeObserver(previewStreamStateObserver2);
                }
            });
        }
    }

    /* renamed from: androidx.camera.view.PreviewView$2 */
    public static /* synthetic */ class C02172 {
        public static final /* synthetic */ int[] $SwitchMap$androidx$camera$view$PreviewView$ImplementationMode;
        public static final /* synthetic */ int[] $SwitchMap$androidx$camera$view$PreviewView$ScaleType;

        static {
            ImplementationMode.values();
            int[] iArr = new int[2];
            $SwitchMap$androidx$camera$view$PreviewView$ImplementationMode = iArr;
            try {
                iArr[ImplementationMode.COMPATIBLE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ImplementationMode[ImplementationMode.PERFORMANCE.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            ScaleType.values();
            int[] iArr2 = new int[6];
            $SwitchMap$androidx$camera$view$PreviewView$ScaleType = iArr2;
            try {
                iArr2[ScaleType.FILL_END.ordinal()] = 1;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[ScaleType.FILL_CENTER.ordinal()] = 2;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[ScaleType.FILL_START.ordinal()] = 3;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[ScaleType.FIT_END.ordinal()] = 4;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[ScaleType.FIT_CENTER.ordinal()] = 5;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[ScaleType.FIT_START.ordinal()] = 6;
            } catch (NoSuchFieldError unused8) {
            }
        }
    }

    public enum ImplementationMode {
        PERFORMANCE(0),
        COMPATIBLE(1);

        private final int mId;

        ImplementationMode(int i2) {
            this.mId = i2;
        }

        public static ImplementationMode fromId(int i2) {
            ImplementationMode[] values = values();
            for (int i3 = 0; i3 < 2; i3++) {
                ImplementationMode implementationMode = values[i3];
                if (implementationMode.mId == i2) {
                    return implementationMode;
                }
            }
            throw new IllegalArgumentException(C1499a.m626l("Unknown implementation mode id ", i2));
        }

        public int getId() {
            return this.mId;
        }
    }

    public class PinchToZoomOnScaleGestureListener extends ScaleGestureDetector.SimpleOnScaleGestureListener {
        public PinchToZoomOnScaleGestureListener() {
        }

        @Override // android.view.ScaleGestureDetector.SimpleOnScaleGestureListener, android.view.ScaleGestureDetector.OnScaleGestureListener
        public boolean onScale(ScaleGestureDetector scaleGestureDetector) {
            CameraController cameraController = PreviewView.this.mCameraController;
            if (cameraController == null) {
                return true;
            }
            cameraController.onPinchToZoom(scaleGestureDetector.getScaleFactor());
            return true;
        }
    }

    public enum ScaleType {
        FILL_START(0),
        FILL_CENTER(1),
        FILL_END(2),
        FIT_START(3),
        FIT_CENTER(4),
        FIT_END(5);

        private final int mId;

        ScaleType(int i2) {
            this.mId = i2;
        }

        public static ScaleType fromId(int i2) {
            ScaleType[] values = values();
            for (int i3 = 0; i3 < 6; i3++) {
                ScaleType scaleType = values[i3];
                if (scaleType.mId == i2) {
                    return scaleType;
                }
            }
            throw new IllegalArgumentException(C1499a.m626l("Unknown scale type id ", i2));
        }

        public int getId() {
            return this.mId;
        }
    }

    public enum StreamState {
        IDLE,
        STREAMING
    }

    @UiThread
    public PreviewView(@NonNull Context context) {
        this(context, null);
    }

    @UseExperimental(markerClass = ExperimentalUseCaseGroup.class)
    private void attachToControllerIfReady(boolean z) {
        Display display = getDisplay();
        ViewPort viewPort = getViewPort();
        if (this.mCameraController == null || viewPort == null || !isAttachedToWindow() || display == null) {
            return;
        }
        try {
            this.mCameraController.attachPreviewSurface(getSurfaceProvider(), viewPort, display);
        } catch (IllegalStateException e2) {
            if (!z) {
                throw e2;
            }
            Logger.m126e(TAG, e2.getMessage(), e2);
        }
    }

    private int getViewPortScaleType() {
        int ordinal = getScaleType().ordinal();
        if (ordinal == 0) {
            return 0;
        }
        int i2 = 1;
        if (ordinal != 1) {
            i2 = 2;
            if (ordinal != 2) {
                i2 = 3;
                if (ordinal != 3 && ordinal != 4 && ordinal != 5) {
                    StringBuilder m586H = C1499a.m586H("Unexpected scale type: ");
                    m586H.append(getScaleType());
                    throw new IllegalStateException(m586H.toString());
                }
            }
        }
        return i2;
    }

    /* renamed from: a */
    public /* synthetic */ void m147a(View view, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9) {
        if ((i4 - i2 == i8 - i6 && i5 - i3 == i9 - i7) ? false : true) {
            redrawPreview();
            attachToControllerIfReady(true);
        }
    }

    @Nullable
    @UiThread
    public Bitmap getBitmap() {
        Threads.checkMainThread();
        PreviewViewImplementation previewViewImplementation = this.mImplementation;
        if (previewViewImplementation == null) {
            return null;
        }
        return previewViewImplementation.getBitmap();
    }

    @Nullable
    @UiThread
    public CameraController getController() {
        Threads.checkMainThread();
        return this.mCameraController;
    }

    @NonNull
    @UiThread
    public ImplementationMode getImplementationMode() {
        Threads.checkMainThread();
        return this.mImplementationMode;
    }

    @NonNull
    @UiThread
    public MeteringPointFactory getMeteringPointFactory() {
        Threads.checkMainThread();
        return this.mPreviewViewMeteringPointFactory;
    }

    @NonNull
    public LiveData<StreamState> getPreviewStreamState() {
        return this.mPreviewStreamStateLiveData;
    }

    @NonNull
    @UiThread
    public ScaleType getScaleType() {
        Threads.checkMainThread();
        return this.mPreviewTransform.getScaleType();
    }

    @NonNull
    @UseExperimental(markerClass = ExperimentalUseCaseGroup.class)
    @UiThread
    public Preview.SurfaceProvider getSurfaceProvider() {
        Threads.checkMainThread();
        return this.mSurfaceProvider;
    }

    @Nullable
    @UiThread
    @ExperimentalUseCaseGroup
    public ViewPort getViewPort() {
        Threads.checkMainThread();
        if (getDisplay() == null) {
            return null;
        }
        return getViewPort(getDisplay().getRotation());
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        addOnLayoutChangeListener(this.mOnLayoutChangeListener);
        PreviewViewImplementation previewViewImplementation = this.mImplementation;
        if (previewViewImplementation != null) {
            previewViewImplementation.onAttachedToWindow();
        }
        attachToControllerIfReady(true);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        removeOnLayoutChangeListener(this.mOnLayoutChangeListener);
        PreviewViewImplementation previewViewImplementation = this.mImplementation;
        if (previewViewImplementation != null) {
            previewViewImplementation.onDetachedFromWindow();
        }
        CameraController cameraController = this.mCameraController;
        if (cameraController != null) {
            cameraController.clearPreviewSurface();
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(@NonNull MotionEvent motionEvent) {
        if (this.mCameraController == null) {
            return super.onTouchEvent(motionEvent);
        }
        boolean z = motionEvent.getPointerCount() == 1;
        boolean z2 = motionEvent.getAction() == 1;
        boolean z3 = motionEvent.getEventTime() - motionEvent.getDownTime() < ((long) ViewConfiguration.getLongPressTimeout());
        if (!z || !z2 || !z3) {
            return this.mScaleGestureDetector.onTouchEvent(motionEvent) || super.onTouchEvent(motionEvent);
        }
        this.mTouchUpEvent = motionEvent;
        performClick();
        return true;
    }

    @Override // android.view.View
    public boolean performClick() {
        if (this.mCameraController != null) {
            MotionEvent motionEvent = this.mTouchUpEvent;
            float x = motionEvent != null ? motionEvent.getX() : getWidth() / 2.0f;
            MotionEvent motionEvent2 = this.mTouchUpEvent;
            this.mCameraController.onTapToFocus(this.mPreviewViewMeteringPointFactory, x, motionEvent2 != null ? motionEvent2.getY() : getHeight() / 2.0f);
        }
        this.mTouchUpEvent = null;
        return super.performClick();
    }

    public void redrawPreview() {
        PreviewViewImplementation previewViewImplementation = this.mImplementation;
        if (previewViewImplementation != null) {
            previewViewImplementation.redrawPreview();
        }
        this.mPreviewViewMeteringPointFactory.recalculate(new Size(getWidth(), getHeight()), getLayoutDirection());
    }

    @UiThread
    public void setController(@Nullable CameraController cameraController) {
        Threads.checkMainThread();
        CameraController cameraController2 = this.mCameraController;
        if (cameraController2 != null && cameraController2 != cameraController) {
            cameraController2.clearPreviewSurface();
        }
        this.mCameraController = cameraController;
        attachToControllerIfReady(false);
    }

    @UiThread
    public void setImplementationMode(@NonNull ImplementationMode implementationMode) {
        Threads.checkMainThread();
        this.mImplementationMode = implementationMode;
    }

    @UiThread
    public void setScaleType(@NonNull ScaleType scaleType) {
        Threads.checkMainThread();
        this.mPreviewTransform.setScaleType(scaleType);
        redrawPreview();
    }

    public boolean shouldUseTextureView(@NonNull SurfaceRequest surfaceRequest, @NonNull ImplementationMode implementationMode) {
        boolean equals = surfaceRequest.getCamera().getCameraInfo().getImplementationType().equals(CameraInfo.IMPLEMENTATION_TYPE_CAMERA2_LEGACY);
        if (surfaceRequest.isRGBA8888Required() || Build.VERSION.SDK_INT <= 24 || equals) {
            return true;
        }
        int ordinal = implementationMode.ordinal();
        if (ordinal == 0) {
            return false;
        }
        if (ordinal == 1) {
            return true;
        }
        throw new IllegalArgumentException("Invalid implementation mode: " + implementationMode);
    }

    @UiThread
    public PreviewView(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    @UiThread
    public PreviewView(@NonNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        this(context, attributeSet, i2, 0);
    }

    @UiThread
    public PreviewView(@NonNull Context context, @Nullable AttributeSet attributeSet, int i2, int i3) {
        super(context, attributeSet, i2, i3);
        ImplementationMode implementationMode = DEFAULT_IMPL_MODE;
        this.mImplementationMode = implementationMode;
        PreviewTransformation previewTransformation = new PreviewTransformation();
        this.mPreviewTransform = previewTransformation;
        this.mPreviewStreamStateLiveData = new MutableLiveData<>(StreamState.IDLE);
        this.mActiveStreamStateObserver = new AtomicReference<>();
        this.mPreviewViewMeteringPointFactory = new PreviewViewMeteringPointFactory(previewTransformation);
        this.mOnLayoutChangeListener = new View.OnLayoutChangeListener() { // from class: e.a.c.k
            @Override // android.view.View.OnLayoutChangeListener
            public final void onLayoutChange(View view, int i4, int i5, int i6, int i7, int i8, int i9, int i10, int i11) {
                PreviewView.this.m147a(view, i4, i5, i6, i7, i8, i9, i10, i11);
            }
        };
        this.mSurfaceProvider = new C02161();
        Threads.checkMainThread();
        Resources.Theme theme = context.getTheme();
        int[] iArr = C0218R.styleable.PreviewView;
        TypedArray obtainStyledAttributes = theme.obtainStyledAttributes(attributeSet, iArr, i2, i3);
        if (Build.VERSION.SDK_INT >= 29) {
            saveAttributeDataForStyleable(context, iArr, attributeSet, obtainStyledAttributes, i2, i3);
        }
        try {
            setScaleType(ScaleType.fromId(obtainStyledAttributes.getInteger(C0218R.styleable.PreviewView_scaleType, previewTransformation.getScaleType().getId())));
            setImplementationMode(ImplementationMode.fromId(obtainStyledAttributes.getInteger(C0218R.styleable.PreviewView_implementationMode, implementationMode.getId())));
            obtainStyledAttributes.recycle();
            this.mScaleGestureDetector = new ScaleGestureDetector(context, new PinchToZoomOnScaleGestureListener());
            if (getBackground() == null) {
                setBackgroundColor(ContextCompat.getColor(getContext(), 17170444));
            }
        } catch (Throwable th) {
            obtainStyledAttributes.recycle();
            throw th;
        }
    }

    @SuppressLint({"WrongConstant"})
    @ExperimentalUseCaseGroup
    @Nullable
    @UiThread
    public ViewPort getViewPort(int i2) {
        Threads.checkMainThread();
        if (getWidth() == 0 || getHeight() == 0) {
            return null;
        }
        return new ViewPort.Builder(new Rational(getWidth(), getHeight()), i2).setScaleType(getViewPortScaleType()).setLayoutDirection(getLayoutDirection()).build();
    }
}
