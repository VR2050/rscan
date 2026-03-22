package androidx.camera.core;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.location.Location;
import android.net.Uri;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Pair;
import android.util.Rational;
import android.util.Size;
import androidx.annotation.GuardedBy;
import androidx.annotation.IntRange;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.UiThread;
import androidx.annotation.VisibleForTesting;
import androidx.arch.core.util.Function;
import androidx.camera.core.ForwardingImageProxy;
import androidx.camera.core.ImageCapture;
import androidx.camera.core.ImageCaptureException;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.ImageSaver;
import androidx.camera.core.UseCase;
import androidx.camera.core.impl.CameraCaptureCallback;
import androidx.camera.core.impl.CameraCaptureFailure;
import androidx.camera.core.impl.CameraCaptureMetaData;
import androidx.camera.core.impl.CameraCaptureResult;
import androidx.camera.core.impl.CameraInternal;
import androidx.camera.core.impl.CaptureBundle;
import androidx.camera.core.impl.CaptureConfig;
import androidx.camera.core.impl.CaptureProcessor;
import androidx.camera.core.impl.CaptureStage;
import androidx.camera.core.impl.Config;
import androidx.camera.core.impl.ConfigProvider;
import androidx.camera.core.impl.DeferrableSurface;
import androidx.camera.core.impl.ImageCaptureConfig;
import androidx.camera.core.impl.ImageInputConfig;
import androidx.camera.core.impl.ImageOutputConfig;
import androidx.camera.core.impl.ImageReaderProxy;
import androidx.camera.core.impl.ImmediateSurface;
import androidx.camera.core.impl.MutableConfig;
import androidx.camera.core.impl.MutableOptionsBundle;
import androidx.camera.core.impl.OptionsBundle;
import androidx.camera.core.impl.SessionConfig;
import androidx.camera.core.impl.UseCaseConfig;
import androidx.camera.core.impl.UseCaseConfigFactory;
import androidx.camera.core.impl.utils.CameraOrientationUtil;
import androidx.camera.core.impl.utils.Exif;
import androidx.camera.core.impl.utils.Threads;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.AsyncFunction;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.FutureChain;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.camera.core.internal.IoConfig;
import androidx.camera.core.internal.TargetConfig;
import androidx.camera.core.internal.UseCaseEventConfig;
import androidx.camera.core.internal.utils.ImageUtil;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.core.util.Preconditions;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;
import p411e.p412a.p413a.RunnableC4255s1;
import p411e.p412a.p413a.p414u1.C4277q;

/* loaded from: classes.dex */
public final class ImageCapture extends UseCase {
    public static final int CAPTURE_MODE_MAXIMIZE_QUALITY = 0;
    public static final int CAPTURE_MODE_MINIMIZE_LATENCY = 1;
    private static final long CHECK_3A_TIMEOUT_IN_MS = 1000;
    private static final int DEFAULT_CAPTURE_MODE = 1;

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public static final Defaults DEFAULT_CONFIG = new Defaults();
    private static final int DEFAULT_FLASH_MODE = 2;
    public static final int ERROR_CAMERA_CLOSED = 3;
    public static final int ERROR_CAPTURE_FAILED = 2;
    public static final int ERROR_FILE_IO = 1;
    public static final int ERROR_INVALID_CAMERA = 4;
    public static final int ERROR_UNKNOWN = 0;
    public static final int FLASH_MODE_AUTO = 0;
    public static final int FLASH_MODE_OFF = 2;
    public static final int FLASH_MODE_ON = 1;
    private static final int FLASH_MODE_UNKNOWN = -1;
    private static final byte JPEG_QUALITY_MAXIMIZE_QUALITY_MODE = 100;
    private static final byte JPEG_QUALITY_MINIMIZE_LATENCY_MODE = 95;
    private static final int MAX_IMAGES = 2;
    private static final String TAG = "ImageCapture";
    private CaptureBundle mCaptureBundle;
    private CaptureConfig mCaptureConfig;
    private final int mCaptureMode;
    private CaptureProcessor mCaptureProcessor;
    private final ImageReaderProxy.OnImageAvailableListener mClosingListener;
    private Rational mCropAspectRatio;
    private DeferrableSurface mDeferrableSurface;
    private final boolean mEnableCheck3AConverged;
    private ExecutorService mExecutor;

    @GuardedBy("mLockedFlashMode")
    private int mFlashMode;
    private ImageCaptureRequestProcessor mImageCaptureRequestProcessor;
    public SafeCloseImageReaderProxy mImageReader;

    @NonNull
    public final Executor mIoExecutor;

    @GuardedBy("mLockedFlashMode")
    private final AtomicReference<Integer> mLockedFlashMode;
    private int mMaxCaptureStages;
    private CameraCaptureCallback mMetadataMatchingCaptureCallback;
    public ProcessingImageReader mProcessingImageReader;
    private final CaptureCallbackChecker mSessionCallbackChecker;
    public SessionConfig.Builder mSessionConfigBuilder;

    /* renamed from: androidx.camera.core.ImageCapture$9 */
    public static /* synthetic */ class C01569 {
        public static final /* synthetic */ int[] $SwitchMap$androidx$camera$core$ImageSaver$SaveError;

        static {
            ImageSaver.SaveError.values();
            int[] iArr = new int[4];
            $SwitchMap$androidx$camera$core$ImageSaver$SaveError = iArr;
            try {
                iArr[ImageSaver.SaveError.FILE_IO_FAILED.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
        }
    }

    public static final class Builder implements UseCaseConfig.Builder<ImageCapture, ImageCaptureConfig, Builder>, ImageOutputConfig.Builder<Builder>, IoConfig.Builder<Builder> {
        private final MutableOptionsBundle mMutableConfig;

        public Builder() {
            this(MutableOptionsBundle.create());
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public static Builder fromConfig(@NonNull Config config) {
            return new Builder(MutableOptionsBundle.from(config));
        }

        @Override // androidx.camera.core.ExtendableBuilder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public MutableConfig getMutableConfig() {
            return this.mMutableConfig;
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setBufferFormat(int i2) {
            getMutableConfig().insertOption(ImageCaptureConfig.OPTION_BUFFER_FORMAT, Integer.valueOf(i2));
            return this;
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setCaptureBundle(@NonNull CaptureBundle captureBundle) {
            getMutableConfig().insertOption(ImageCaptureConfig.OPTION_CAPTURE_BUNDLE, captureBundle);
            return this;
        }

        @NonNull
        public Builder setCaptureMode(int i2) {
            getMutableConfig().insertOption(ImageCaptureConfig.OPTION_IMAGE_CAPTURE_MODE, Integer.valueOf(i2));
            return this;
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setCaptureProcessor(@NonNull CaptureProcessor captureProcessor) {
            getMutableConfig().insertOption(ImageCaptureConfig.OPTION_CAPTURE_PROCESSOR, captureProcessor);
            return this;
        }

        @NonNull
        public Builder setFlashMode(int i2) {
            getMutableConfig().insertOption(ImageCaptureConfig.OPTION_FLASH_MODE, Integer.valueOf(i2));
            return this;
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setImageReaderProxyProvider(@NonNull ImageReaderProxyProvider imageReaderProxyProvider) {
            getMutableConfig().insertOption(ImageCaptureConfig.OPTION_IMAGE_READER_PROXY_PROVIDER, imageReaderProxyProvider);
            return this;
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setMaxCaptureStages(int i2) {
            getMutableConfig().insertOption(ImageCaptureConfig.OPTION_MAX_CAPTURE_STAGES, Integer.valueOf(i2));
            return this;
        }

        @Override // androidx.camera.core.impl.ImageOutputConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public /* bridge */ /* synthetic */ Builder setSupportedResolutions(@NonNull List list) {
            return setSupportedResolutions((List<Pair<Integer, Size[]>>) list);
        }

        @Override // androidx.camera.core.internal.TargetConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public /* bridge */ /* synthetic */ Object setTargetClass(@NonNull Class cls) {
            return setTargetClass((Class<ImageCapture>) cls);
        }

        private Builder(MutableOptionsBundle mutableOptionsBundle) {
            this.mMutableConfig = mutableOptionsBundle;
            Class cls = (Class) mutableOptionsBundle.retrieveOption(TargetConfig.OPTION_TARGET_CLASS, null);
            if (cls == null || cls.equals(ImageCapture.class)) {
                setTargetClass(ImageCapture.class);
                return;
            }
            throw new IllegalArgumentException("Invalid target class configuration for " + this + ": " + cls);
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public static Builder fromConfig(@NonNull ImageCaptureConfig imageCaptureConfig) {
            return new Builder(MutableOptionsBundle.from((Config) imageCaptureConfig));
        }

        @Override // androidx.camera.core.ExtendableBuilder
        @NonNull
        public ImageCapture build() {
            int intValue;
            if (getMutableConfig().retrieveOption(ImageOutputConfig.OPTION_TARGET_ASPECT_RATIO, null) != null && getMutableConfig().retrieveOption(ImageOutputConfig.OPTION_TARGET_RESOLUTION, null) != null) {
                throw new IllegalArgumentException("Cannot use both setTargetResolution and setTargetAspectRatio on the same config.");
            }
            Integer num = (Integer) getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_BUFFER_FORMAT, null);
            if (num != null) {
                Preconditions.checkArgument(getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_CAPTURE_PROCESSOR, null) == null, "Cannot set buffer format with CaptureProcessor defined.");
                getMutableConfig().insertOption(ImageInputConfig.OPTION_INPUT_FORMAT, num);
            } else if (getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_CAPTURE_PROCESSOR, null) != null) {
                getMutableConfig().insertOption(ImageInputConfig.OPTION_INPUT_FORMAT, 35);
            } else {
                getMutableConfig().insertOption(ImageInputConfig.OPTION_INPUT_FORMAT, 256);
            }
            ImageCapture imageCapture = new ImageCapture(getUseCaseConfig());
            Size size = (Size) getMutableConfig().retrieveOption(ImageOutputConfig.OPTION_TARGET_RESOLUTION, null);
            if (size != null) {
                imageCapture.setCropAspectRatio(new Rational(size.getWidth(), size.getHeight()));
            }
            Preconditions.checkArgument(((Integer) getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_MAX_CAPTURE_STAGES, 2)).intValue() >= 1, "Maximum outstanding image count must be at least 1");
            Preconditions.checkNotNull((Executor) getMutableConfig().retrieveOption(IoConfig.OPTION_IO_EXECUTOR, CameraXExecutors.ioExecutor()), "The IO executor can't be null");
            MutableConfig mutableConfig = getMutableConfig();
            Config.Option<Integer> option = ImageCaptureConfig.OPTION_FLASH_MODE;
            if (!mutableConfig.containsOption(option) || (intValue = ((Integer) getMutableConfig().retrieveOption(option)).intValue()) == 0 || intValue == 1 || intValue == 2) {
                return imageCapture;
            }
            throw new IllegalArgumentException(C1499a.m626l("The flash mode is not allowed to set: ", intValue));
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.UseCaseConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public ImageCaptureConfig getUseCaseConfig() {
            return new ImageCaptureConfig(OptionsBundle.from(this.mMutableConfig));
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.UseCaseConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setCameraSelector(@NonNull CameraSelector cameraSelector) {
            getMutableConfig().insertOption(UseCaseConfig.OPTION_CAMERA_SELECTOR, cameraSelector);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.UseCaseConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setCaptureOptionUnpacker(@NonNull CaptureConfig.OptionUnpacker optionUnpacker) {
            getMutableConfig().insertOption(UseCaseConfig.OPTION_CAPTURE_CONFIG_UNPACKER, optionUnpacker);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.UseCaseConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setDefaultCaptureConfig(@NonNull CaptureConfig captureConfig) {
            getMutableConfig().insertOption(UseCaseConfig.OPTION_DEFAULT_CAPTURE_CONFIG, captureConfig);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.ImageOutputConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setDefaultResolution(@NonNull Size size) {
            getMutableConfig().insertOption(ImageOutputConfig.OPTION_DEFAULT_RESOLUTION, size);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.UseCaseConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setDefaultSessionConfig(@NonNull SessionConfig sessionConfig) {
            getMutableConfig().insertOption(UseCaseConfig.OPTION_DEFAULT_SESSION_CONFIG, sessionConfig);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.internal.IoConfig.Builder
        @NonNull
        public Builder setIoExecutor(@NonNull Executor executor) {
            getMutableConfig().insertOption(IoConfig.OPTION_IO_EXECUTOR, executor);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.ImageOutputConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setMaxResolution(@NonNull Size size) {
            getMutableConfig().insertOption(ImageOutputConfig.OPTION_MAX_RESOLUTION, size);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.UseCaseConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setSessionOptionUnpacker(@NonNull SessionConfig.OptionUnpacker optionUnpacker) {
            getMutableConfig().insertOption(UseCaseConfig.OPTION_SESSION_CONFIG_UNPACKER, optionUnpacker);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.ImageOutputConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setSupportedResolutions(@NonNull List<Pair<Integer, Size[]>> list) {
            getMutableConfig().insertOption(ImageOutputConfig.OPTION_SUPPORTED_RESOLUTIONS, list);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.UseCaseConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setSurfaceOccupancyPriority(int i2) {
            getMutableConfig().insertOption(UseCaseConfig.OPTION_SURFACE_OCCUPANCY_PRIORITY, Integer.valueOf(i2));
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.ImageOutputConfig.Builder
        @NonNull
        public Builder setTargetAspectRatio(int i2) {
            getMutableConfig().insertOption(ImageOutputConfig.OPTION_TARGET_ASPECT_RATIO, Integer.valueOf(i2));
            return this;
        }

        @Override // androidx.camera.core.internal.TargetConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setTargetClass(@NonNull Class<ImageCapture> cls) {
            getMutableConfig().insertOption(TargetConfig.OPTION_TARGET_CLASS, cls);
            if (getMutableConfig().retrieveOption(TargetConfig.OPTION_TARGET_NAME, null) == null) {
                setTargetName(cls.getCanonicalName() + "-" + UUID.randomUUID());
            }
            return this;
        }

        @Override // androidx.camera.core.internal.TargetConfig.Builder
        @NonNull
        public Builder setTargetName(@NonNull String str) {
            getMutableConfig().insertOption(TargetConfig.OPTION_TARGET_NAME, str);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.ImageOutputConfig.Builder
        @NonNull
        public Builder setTargetResolution(@NonNull Size size) {
            getMutableConfig().insertOption(ImageOutputConfig.OPTION_TARGET_RESOLUTION, size);
            return this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // androidx.camera.core.impl.ImageOutputConfig.Builder
        @NonNull
        public Builder setTargetRotation(int i2) {
            getMutableConfig().insertOption(ImageOutputConfig.OPTION_TARGET_ROTATION, Integer.valueOf(i2));
            return this;
        }

        @Override // androidx.camera.core.internal.UseCaseEventConfig.Builder
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Builder setUseCaseEventCallback(@NonNull UseCase.EventCallback eventCallback) {
            getMutableConfig().insertOption(UseCaseEventConfig.OPTION_USE_CASE_EVENT_CALLBACK, eventCallback);
            return this;
        }
    }

    public static final class CaptureCallbackChecker extends CameraCaptureCallback {
        private static final long NO_TIMEOUT = 0;
        private final Set<CaptureResultListener> mCaptureResultListeners = new HashSet();

        public interface CaptureResultChecker<T> {
            @Nullable
            T check(@NonNull CameraCaptureResult cameraCaptureResult);
        }

        public interface CaptureResultListener {
            boolean onCaptureResult(@NonNull CameraCaptureResult cameraCaptureResult);
        }

        private void deliverCaptureResultToListeners(@NonNull CameraCaptureResult cameraCaptureResult) {
            synchronized (this.mCaptureResultListeners) {
                HashSet hashSet = null;
                Iterator it = new HashSet(this.mCaptureResultListeners).iterator();
                while (it.hasNext()) {
                    CaptureResultListener captureResultListener = (CaptureResultListener) it.next();
                    if (captureResultListener.onCaptureResult(cameraCaptureResult)) {
                        if (hashSet == null) {
                            hashSet = new HashSet();
                        }
                        hashSet.add(captureResultListener);
                    }
                }
                if (hashSet != null) {
                    this.mCaptureResultListeners.removeAll(hashSet);
                }
            }
        }

        public void addListener(CaptureResultListener captureResultListener) {
            synchronized (this.mCaptureResultListeners) {
                this.mCaptureResultListeners.add(captureResultListener);
            }
        }

        public <T> InterfaceFutureC2413a<T> checkCaptureResult(CaptureResultChecker<T> captureResultChecker) {
            return checkCaptureResult(captureResultChecker, 0L, null);
        }

        @Override // androidx.camera.core.impl.CameraCaptureCallback
        public void onCaptureCompleted(@NonNull CameraCaptureResult cameraCaptureResult) {
            deliverCaptureResultToListeners(cameraCaptureResult);
        }

        public <T> InterfaceFutureC2413a<T> checkCaptureResult(final CaptureResultChecker<T> captureResultChecker, final long j2, final T t) {
            if (j2 < 0) {
                throw new IllegalArgumentException(C1499a.m630p("Invalid timeout value: ", j2));
            }
            final long elapsedRealtime = j2 != 0 ? SystemClock.elapsedRealtime() : 0L;
            return CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.u
                @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
                public final Object attachCompleter(final CallbackToFutureAdapter.Completer completer) {
                    final ImageCapture.CaptureCallbackChecker captureCallbackChecker = ImageCapture.CaptureCallbackChecker.this;
                    final ImageCapture.CaptureCallbackChecker.CaptureResultChecker captureResultChecker2 = captureResultChecker;
                    final long j3 = elapsedRealtime;
                    final long j4 = j2;
                    final Object obj = t;
                    Objects.requireNonNull(captureCallbackChecker);
                    captureCallbackChecker.addListener(new ImageCapture.CaptureCallbackChecker.CaptureResultListener() { // from class: androidx.camera.core.ImageCapture.CaptureCallbackChecker.1
                        @Override // androidx.camera.core.ImageCapture.CaptureCallbackChecker.CaptureResultListener
                        public boolean onCaptureResult(@NonNull CameraCaptureResult cameraCaptureResult) {
                            Object check = captureResultChecker2.check(cameraCaptureResult);
                            if (check != null) {
                                completer.set(check);
                                return true;
                            }
                            if (j3 <= 0 || SystemClock.elapsedRealtime() - j3 <= j4) {
                                return false;
                            }
                            completer.set(obj);
                            return true;
                        }
                    });
                    return "checkCaptureResult";
                }
            });
        }
    }

    public static final class CaptureFailedException extends RuntimeException {
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public CaptureFailedException(String str, Throwable th) {
            super(str, th);
        }

        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public CaptureFailedException(String str) {
            super(str);
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public @interface CaptureMode {
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public static final class Defaults implements ConfigProvider<ImageCaptureConfig> {
        private static final int DEFAULT_ASPECT_RATIO = 0;
        private static final ImageCaptureConfig DEFAULT_CONFIG = new Builder().setSurfaceOccupancyPriority(4).setTargetAspectRatio(0).getUseCaseConfig();
        private static final int DEFAULT_SURFACE_OCCUPANCY_PRIORITY = 4;

        @Override // androidx.camera.core.impl.ConfigProvider
        @NonNull
        public ImageCaptureConfig getConfig() {
            return DEFAULT_CONFIG;
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public @interface FlashMode {
    }

    @Retention(RetentionPolicy.SOURCE)
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public @interface ImageCaptureError {
    }

    @VisibleForTesting
    public static class ImageCaptureRequest {

        @NonNull
        private final OnImageCapturedCallback mCallback;
        public AtomicBoolean mDispatched = new AtomicBoolean(false);

        @IntRange(from = 1, m111to = 100)
        public final int mJpegQuality;

        @NonNull
        private final Executor mListenerExecutor;
        public final int mRotationDegrees;
        private final Rational mTargetRatio;
        private final Rect mViewPortCropRect;

        public ImageCaptureRequest(int i2, @IntRange(from = 1, m111to = 100) int i3, Rational rational, @Nullable Rect rect, @NonNull Executor executor, @NonNull OnImageCapturedCallback onImageCapturedCallback) {
            this.mRotationDegrees = i2;
            this.mJpegQuality = i3;
            if (rational != null) {
                Preconditions.checkArgument(!rational.isZero(), "Target ratio cannot be zero");
                Preconditions.checkArgument(rational.floatValue() > 0.0f, "Target ratio must be positive");
            }
            this.mTargetRatio = rational;
            this.mViewPortCropRect = rect;
            this.mListenerExecutor = executor;
            this.mCallback = onImageCapturedCallback;
        }

        @NonNull
        public static Rect getDispatchCropRect(@NonNull Rect rect, int i2, @NonNull Size size, int i3) {
            Matrix matrix = new Matrix();
            matrix.setRotate(i3 - i2);
            float[] sizeToVertexes = ImageUtil.sizeToVertexes(size);
            matrix.mapPoints(sizeToVertexes);
            matrix.postTranslate(-ImageUtil.min(sizeToVertexes[0], sizeToVertexes[2], sizeToVertexes[4], sizeToVertexes[6]), -ImageUtil.min(sizeToVertexes[1], sizeToVertexes[3], sizeToVertexes[5], sizeToVertexes[7]));
            matrix.invert(matrix);
            RectF rectF = new RectF();
            matrix.mapRect(rectF, new RectF(rect));
            rectF.sort();
            Rect rect2 = new Rect();
            rectF.round(rect2);
            return rect2;
        }

        /* renamed from: a */
        public /* synthetic */ void m121a(ImageProxy imageProxy) {
            this.mCallback.onCaptureSuccess(imageProxy);
        }

        /* renamed from: b */
        public /* synthetic */ void m122b(int i2, String str, Throwable th) {
            this.mCallback.onError(new ImageCaptureException(i2, str, th));
        }

        public void dispatchImage(ImageProxy imageProxy) {
            Size size;
            int rotation;
            if (!this.mDispatched.compareAndSet(false, true)) {
                imageProxy.close();
                return;
            }
            if (imageProxy.getFormat() == 256) {
                try {
                    ByteBuffer buffer = imageProxy.getPlanes()[0].getBuffer();
                    buffer.rewind();
                    byte[] bArr = new byte[buffer.capacity()];
                    buffer.get(bArr);
                    Exif createFromInputStream = Exif.createFromInputStream(new ByteArrayInputStream(bArr));
                    buffer.rewind();
                    size = new Size(createFromInputStream.getWidth(), createFromInputStream.getHeight());
                    rotation = createFromInputStream.getRotation();
                } catch (IOException e2) {
                    notifyCallbackError(1, "Unable to parse JPEG exif", e2);
                    imageProxy.close();
                    return;
                }
            } else {
                size = new Size(imageProxy.getWidth(), imageProxy.getHeight());
                rotation = this.mRotationDegrees;
            }
            final SettableImageProxy settableImageProxy = new SettableImageProxy(imageProxy, size, ImmutableImageInfo.create(imageProxy.getImageInfo().getTagBundle(), imageProxy.getImageInfo().getTimestamp(), rotation));
            Rect rect = this.mViewPortCropRect;
            if (rect != null) {
                settableImageProxy.setCropRect(getDispatchCropRect(rect, this.mRotationDegrees, size, rotation));
            } else {
                Rational rational = this.mTargetRatio;
                if (rational != null) {
                    if (rotation % 180 != 0) {
                        rational = new Rational(this.mTargetRatio.getDenominator(), this.mTargetRatio.getNumerator());
                    }
                    Size size2 = new Size(settableImageProxy.getWidth(), settableImageProxy.getHeight());
                    if (ImageUtil.isAspectRatioValid(size2, rational)) {
                        settableImageProxy.setCropRect(ImageUtil.computeCropRectFromAspectRatio(size2, rational));
                    }
                }
            }
            try {
                this.mListenerExecutor.execute(new Runnable() { // from class: e.a.a.y
                    @Override // java.lang.Runnable
                    public final void run() {
                        ImageCapture.ImageCaptureRequest.this.m121a(settableImageProxy);
                    }
                });
            } catch (RejectedExecutionException unused) {
                Logger.m125e(ImageCapture.TAG, "Unable to post to the supplied executor.");
                imageProxy.close();
            }
        }

        public void notifyCallbackError(final int i2, final String str, final Throwable th) {
            if (this.mDispatched.compareAndSet(false, true)) {
                try {
                    this.mListenerExecutor.execute(new Runnable() { // from class: e.a.a.x
                        @Override // java.lang.Runnable
                        public final void run() {
                            ImageCapture.ImageCaptureRequest.this.m122b(i2, str, th);
                        }
                    });
                } catch (RejectedExecutionException unused) {
                    Logger.m125e(ImageCapture.TAG, "Unable to post to the supplied executor.");
                }
            }
        }
    }

    @VisibleForTesting
    public static class ImageCaptureRequestProcessor implements ForwardingImageProxy.OnImageCloseListener {

        @GuardedBy("mLock")
        private final ImageCaptor mImageCaptor;
        private final int mMaxImages;

        @GuardedBy("mLock")
        private final Deque<ImageCaptureRequest> mPendingRequests = new ArrayDeque();

        @GuardedBy("mLock")
        public ImageCaptureRequest mCurrentRequest = null;

        @GuardedBy("mLock")
        public InterfaceFutureC2413a<ImageProxy> mCurrentRequestFuture = null;

        @GuardedBy("mLock")
        public int mOutstandingImages = 0;
        public final Object mLock = new Object();

        public interface ImageCaptor {
            @NonNull
            InterfaceFutureC2413a<ImageProxy> capture(@NonNull ImageCaptureRequest imageCaptureRequest);
        }

        public ImageCaptureRequestProcessor(int i2, @NonNull ImageCaptor imageCaptor) {
            this.mMaxImages = i2;
            this.mImageCaptor = imageCaptor;
        }

        public void cancelRequests(@NonNull Throwable th) {
            ImageCaptureRequest imageCaptureRequest;
            InterfaceFutureC2413a<ImageProxy> interfaceFutureC2413a;
            ArrayList arrayList;
            synchronized (this.mLock) {
                imageCaptureRequest = this.mCurrentRequest;
                this.mCurrentRequest = null;
                interfaceFutureC2413a = this.mCurrentRequestFuture;
                this.mCurrentRequestFuture = null;
                arrayList = new ArrayList(this.mPendingRequests);
                this.mPendingRequests.clear();
            }
            if (imageCaptureRequest != null && interfaceFutureC2413a != null) {
                imageCaptureRequest.notifyCallbackError(ImageCapture.getError(th), th.getMessage(), th);
                interfaceFutureC2413a.cancel(true);
            }
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                ((ImageCaptureRequest) it.next()).notifyCallbackError(ImageCapture.getError(th), th.getMessage(), th);
            }
        }

        @Override // androidx.camera.core.ForwardingImageProxy.OnImageCloseListener
        public void onImageClose(ImageProxy imageProxy) {
            synchronized (this.mLock) {
                this.mOutstandingImages--;
                processNextRequest();
            }
        }

        public void processNextRequest() {
            synchronized (this.mLock) {
                if (this.mCurrentRequest != null) {
                    return;
                }
                if (this.mOutstandingImages >= this.mMaxImages) {
                    Logger.m129w(ImageCapture.TAG, "Too many acquire images. Close image to be able to process next.");
                    return;
                }
                final ImageCaptureRequest poll = this.mPendingRequests.poll();
                if (poll == null) {
                    return;
                }
                this.mCurrentRequest = poll;
                InterfaceFutureC2413a<ImageProxy> capture = this.mImageCaptor.capture(poll);
                this.mCurrentRequestFuture = capture;
                Futures.addCallback(capture, new FutureCallback<ImageProxy>() { // from class: androidx.camera.core.ImageCapture.ImageCaptureRequestProcessor.1
                    @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                    public void onFailure(Throwable th) {
                        synchronized (ImageCaptureRequestProcessor.this.mLock) {
                            if (!(th instanceof CancellationException)) {
                                poll.notifyCallbackError(ImageCapture.getError(th), th != null ? th.getMessage() : "Unknown error", th);
                            }
                            ImageCaptureRequestProcessor imageCaptureRequestProcessor = ImageCaptureRequestProcessor.this;
                            imageCaptureRequestProcessor.mCurrentRequest = null;
                            imageCaptureRequestProcessor.mCurrentRequestFuture = null;
                            imageCaptureRequestProcessor.processNextRequest();
                        }
                    }

                    @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                    public void onSuccess(@Nullable ImageProxy imageProxy) {
                        synchronized (ImageCaptureRequestProcessor.this.mLock) {
                            Preconditions.checkNotNull(imageProxy);
                            SingleCloseImageProxy singleCloseImageProxy = new SingleCloseImageProxy(imageProxy);
                            singleCloseImageProxy.addOnImageCloseListener(ImageCaptureRequestProcessor.this);
                            ImageCaptureRequestProcessor.this.mOutstandingImages++;
                            poll.dispatchImage(singleCloseImageProxy);
                            ImageCaptureRequestProcessor imageCaptureRequestProcessor = ImageCaptureRequestProcessor.this;
                            imageCaptureRequestProcessor.mCurrentRequest = null;
                            imageCaptureRequestProcessor.mCurrentRequestFuture = null;
                            imageCaptureRequestProcessor.processNextRequest();
                        }
                    }
                }, CameraXExecutors.directExecutor());
            }
        }

        public void sendRequest(@NonNull ImageCaptureRequest imageCaptureRequest) {
            synchronized (this.mLock) {
                this.mPendingRequests.offer(imageCaptureRequest);
                Locale locale = Locale.US;
                Object[] objArr = new Object[2];
                objArr[0] = Integer.valueOf(this.mCurrentRequest != null ? 1 : 0);
                objArr[1] = Integer.valueOf(this.mPendingRequests.size());
                Logger.m123d(ImageCapture.TAG, String.format(locale, "Send image capture request [current, pending] = [%d, %d]", objArr));
                processNextRequest();
            }
        }
    }

    public static final class Metadata {
        private boolean mIsReversedHorizontal;
        private boolean mIsReversedHorizontalSet = false;
        private boolean mIsReversedVertical;

        @Nullable
        private Location mLocation;

        @Nullable
        public Location getLocation() {
            return this.mLocation;
        }

        public boolean isReversedHorizontal() {
            return this.mIsReversedHorizontal;
        }

        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public boolean isReversedHorizontalSet() {
            return this.mIsReversedHorizontalSet;
        }

        public boolean isReversedVertical() {
            return this.mIsReversedVertical;
        }

        public void setLocation(@Nullable Location location) {
            this.mLocation = location;
        }

        public void setReversedHorizontal(boolean z) {
            this.mIsReversedHorizontal = z;
            this.mIsReversedHorizontalSet = true;
        }

        public void setReversedVertical(boolean z) {
            this.mIsReversedVertical = z;
        }
    }

    public static abstract class OnImageCapturedCallback {
        public void onCaptureSuccess(@NonNull ImageProxy imageProxy) {
        }

        public void onError(@NonNull ImageCaptureException imageCaptureException) {
        }
    }

    public interface OnImageSavedCallback {
        void onError(@NonNull ImageCaptureException imageCaptureException);

        void onImageSaved(@NonNull OutputFileResults outputFileResults);
    }

    public static final class OutputFileOptions {
        private static final Metadata EMPTY_METADATA = new Metadata();

        @Nullable
        private final ContentResolver mContentResolver;

        @Nullable
        private final ContentValues mContentValues;

        @Nullable
        private final File mFile;

        @NonNull
        private final Metadata mMetadata;

        @Nullable
        private final OutputStream mOutputStream;

        @Nullable
        private final Uri mSaveCollection;

        public OutputFileOptions(@Nullable File file, @Nullable ContentResolver contentResolver, @Nullable Uri uri, @Nullable ContentValues contentValues, @Nullable OutputStream outputStream, @Nullable Metadata metadata) {
            this.mFile = file;
            this.mContentResolver = contentResolver;
            this.mSaveCollection = uri;
            this.mContentValues = contentValues;
            this.mOutputStream = outputStream;
            this.mMetadata = metadata == null ? EMPTY_METADATA : metadata;
        }

        @Nullable
        public ContentResolver getContentResolver() {
            return this.mContentResolver;
        }

        @Nullable
        public ContentValues getContentValues() {
            return this.mContentValues;
        }

        @Nullable
        public File getFile() {
            return this.mFile;
        }

        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public Metadata getMetadata() {
            return this.mMetadata;
        }

        @Nullable
        public OutputStream getOutputStream() {
            return this.mOutputStream;
        }

        @Nullable
        public Uri getSaveCollection() {
            return this.mSaveCollection;
        }

        public static final class Builder {

            @Nullable
            private ContentResolver mContentResolver;

            @Nullable
            private ContentValues mContentValues;

            @Nullable
            private File mFile;

            @Nullable
            private Metadata mMetadata;

            @Nullable
            private OutputStream mOutputStream;

            @Nullable
            private Uri mSaveCollection;

            public Builder(@NonNull File file) {
                this.mFile = file;
            }

            @NonNull
            public OutputFileOptions build() {
                return new OutputFileOptions(this.mFile, this.mContentResolver, this.mSaveCollection, this.mContentValues, this.mOutputStream, this.mMetadata);
            }

            @NonNull
            public Builder setMetadata(@NonNull Metadata metadata) {
                this.mMetadata = metadata;
                return this;
            }

            public Builder(@NonNull ContentResolver contentResolver, @NonNull Uri uri, @NonNull ContentValues contentValues) {
                this.mContentResolver = contentResolver;
                this.mSaveCollection = uri;
                this.mContentValues = contentValues;
            }

            public Builder(@NonNull OutputStream outputStream) {
                this.mOutputStream = outputStream;
            }
        }
    }

    public static class OutputFileResults {

        @Nullable
        private Uri mSavedUri;

        public OutputFileResults(@Nullable Uri uri) {
            this.mSavedUri = uri;
        }

        @Nullable
        public Uri getSavedUri() {
            return this.mSavedUri;
        }
    }

    public static final class TakePictureState {
        public CameraCaptureResult mPreCaptureState = CameraCaptureResult.EmptyCameraCaptureResult.create();
        public boolean mIsAfTriggered = false;
        public boolean mIsAePrecaptureTriggered = false;
    }

    public ImageCapture(@NonNull ImageCaptureConfig imageCaptureConfig) {
        super(imageCaptureConfig);
        this.mSessionCallbackChecker = new CaptureCallbackChecker();
        this.mClosingListener = new ImageReaderProxy.OnImageAvailableListener() { // from class: e.a.a.l0
            @Override // androidx.camera.core.impl.ImageReaderProxy.OnImageAvailableListener
            public final void onImageAvailable(ImageReaderProxy imageReaderProxy) {
                int i2 = ImageCapture.ERROR_UNKNOWN;
                try {
                    ImageProxy acquireLatestImage = imageReaderProxy.acquireLatestImage();
                    try {
                        String str = "Discarding ImageProxy which was inadvertently acquired: " + acquireLatestImage;
                        if (acquireLatestImage != null) {
                            acquireLatestImage.close();
                        }
                    } finally {
                    }
                } catch (IllegalStateException unused) {
                }
            }
        };
        this.mLockedFlashMode = new AtomicReference<>(null);
        this.mFlashMode = -1;
        this.mCropAspectRatio = null;
        ImageCaptureConfig imageCaptureConfig2 = (ImageCaptureConfig) getCurrentConfig();
        if (imageCaptureConfig2.containsOption(ImageCaptureConfig.OPTION_IMAGE_CAPTURE_MODE)) {
            this.mCaptureMode = imageCaptureConfig2.getCaptureMode();
        } else {
            this.mCaptureMode = 1;
        }
        this.mIoExecutor = (Executor) Preconditions.checkNotNull(imageCaptureConfig2.getIoExecutor(CameraXExecutors.ioExecutor()));
        if (this.mCaptureMode == 0) {
            this.mEnableCheck3AConverged = true;
        } else {
            this.mEnableCheck3AConverged = false;
        }
    }

    private void abortImageCaptureRequests() {
        this.mImageCaptureRequestProcessor.cancelRequests(new CameraClosedException("Camera is closed."));
    }

    private CaptureBundle getCaptureBundle(CaptureBundle captureBundle) {
        List<CaptureStage> captureStages = this.mCaptureBundle.getCaptureStages();
        return (captureStages == null || captureStages.isEmpty()) ? captureBundle : CaptureBundles.createCaptureBundle(captureStages);
    }

    public static int getError(Throwable th) {
        if (th instanceof CameraClosedException) {
            return 3;
        }
        return th instanceof CaptureFailedException ? 2 : 0;
    }

    @IntRange(from = 1, m111to = 100)
    private int getJpegQuality() {
        int i2 = this.mCaptureMode;
        if (i2 == 0) {
            return 100;
        }
        if (i2 == 1) {
            return 95;
        }
        throw new IllegalStateException(C1499a.m580B(C1499a.m586H("CaptureMode "), this.mCaptureMode, " is invalid"));
    }

    private InterfaceFutureC2413a<CameraCaptureResult> getPreCaptureStateIfNeeded() {
        return (this.mEnableCheck3AConverged || getFlashMode() == 0) ? this.mSessionCallbackChecker.checkCaptureResult(new CaptureCallbackChecker.CaptureResultChecker<CameraCaptureResult>() { // from class: androidx.camera.core.ImageCapture.6
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // androidx.camera.core.ImageCapture.CaptureCallbackChecker.CaptureResultChecker
            public CameraCaptureResult check(@NonNull CameraCaptureResult cameraCaptureResult) {
                if (Logger.isDebugEnabled(ImageCapture.TAG)) {
                    StringBuilder m586H = C1499a.m586H("preCaptureState, AE=");
                    m586H.append(cameraCaptureResult.getAeState());
                    m586H.append(" AF =");
                    m586H.append(cameraCaptureResult.getAfState());
                    m586H.append(" AWB=");
                    m586H.append(cameraCaptureResult.getAwbState());
                    Logger.m123d(ImageCapture.TAG, m586H.toString());
                }
                return cameraCaptureResult;
            }
        }) : Futures.immediateFuture(null);
    }

    private void lockFlashMode() {
        synchronized (this.mLockedFlashMode) {
            if (this.mLockedFlashMode.get() != null) {
                return;
            }
            this.mLockedFlashMode.set(Integer.valueOf(getFlashMode()));
        }
    }

    private InterfaceFutureC2413a<Void> preTakePicture(final TakePictureState takePictureState) {
        lockFlashMode();
        return FutureChain.from(getPreCaptureStateIfNeeded()).transformAsync(new AsyncFunction() { // from class: e.a.a.k0
            @Override // androidx.camera.core.impl.utils.futures.AsyncFunction
            public final InterfaceFutureC2413a apply(Object obj) {
                ImageCapture imageCapture = ImageCapture.this;
                ImageCapture.TakePictureState takePictureState2 = takePictureState;
                Objects.requireNonNull(imageCapture);
                takePictureState2.mPreCaptureState = (CameraCaptureResult) obj;
                imageCapture.triggerAfIfNeeded(takePictureState2);
                return imageCapture.isAePrecaptureRequired(takePictureState2) ? imageCapture.triggerAePrecapture(takePictureState2) : Futures.immediateFuture(null);
            }
        }, this.mExecutor).transformAsync(new AsyncFunction() { // from class: e.a.a.c0
            @Override // androidx.camera.core.impl.utils.futures.AsyncFunction
            public final InterfaceFutureC2413a apply(Object obj) {
                return ImageCapture.this.check3AConverged(takePictureState);
            }
        }, this.mExecutor).transform(new Function() { // from class: e.a.a.b0
            @Override // androidx.arch.core.util.Function
            public final Object apply(Object obj) {
                int i2 = ImageCapture.ERROR_UNKNOWN;
                return null;
            }
        }, this.mExecutor);
    }

    @UiThread
    private void sendImageCaptureRequest(@NonNull Executor executor, @NonNull final OnImageCapturedCallback onImageCapturedCallback) {
        CameraInternal camera = getCamera();
        if (camera == null) {
            executor.execute(new Runnable() { // from class: e.a.a.z
                @Override // java.lang.Runnable
                public final void run() {
                    ImageCapture imageCapture = ImageCapture.this;
                    ImageCapture.OnImageCapturedCallback onImageCapturedCallback2 = onImageCapturedCallback;
                    Objects.requireNonNull(imageCapture);
                    onImageCapturedCallback2.onError(new ImageCaptureException(4, "Not bound to a valid Camera [" + imageCapture + "]", null));
                }
            });
        } else {
            this.mImageCaptureRequestProcessor.sendRequest(new ImageCaptureRequest(getRelativeRotation(camera), getJpegQuality(), this.mCropAspectRatio, getViewPortCropRect(), executor, onImageCapturedCallback));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: takePictureInternal, reason: merged with bridge method [inline-methods] */
    public InterfaceFutureC2413a<ImageProxy> m119a(@NonNull final ImageCaptureRequest imageCaptureRequest) {
        return CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.h0
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                ImageCapture.this.m120b(imageCaptureRequest, completer);
                return "takePictureInternal";
            }
        });
    }

    private void triggerAf(TakePictureState takePictureState) {
        Logger.m123d(TAG, "triggerAf");
        takePictureState.mIsAfTriggered = true;
        getCameraControl().triggerAf().addListener(new Runnable() { // from class: e.a.a.f0
            @Override // java.lang.Runnable
            public final void run() {
                int i2 = ImageCapture.ERROR_UNKNOWN;
            }
        }, CameraXExecutors.directExecutor());
    }

    private void trySetFlashModeToCameraControl() {
        synchronized (this.mLockedFlashMode) {
            if (this.mLockedFlashMode.get() != null) {
                return;
            }
            getCameraControl().setFlashMode(getFlashMode());
        }
    }

    private void unlockFlashMode() {
        synchronized (this.mLockedFlashMode) {
            Integer andSet = this.mLockedFlashMode.getAndSet(null);
            if (andSet == null) {
                return;
            }
            if (andSet.intValue() != getFlashMode()) {
                trySetFlashModeToCameraControl();
            }
        }
    }

    /* renamed from: b */
    public /* synthetic */ Object m120b(final ImageCaptureRequest imageCaptureRequest, final CallbackToFutureAdapter.Completer completer) {
        this.mImageReader.setOnImageAvailableListener(new ImageReaderProxy.OnImageAvailableListener() { // from class: e.a.a.d0
            @Override // androidx.camera.core.impl.ImageReaderProxy.OnImageAvailableListener
            public final void onImageAvailable(ImageReaderProxy imageReaderProxy) {
                CallbackToFutureAdapter.Completer completer2 = CallbackToFutureAdapter.Completer.this;
                int i2 = ImageCapture.ERROR_UNKNOWN;
                try {
                    ImageProxy acquireLatestImage = imageReaderProxy.acquireLatestImage();
                    if (acquireLatestImage == null) {
                        completer2.setException(new IllegalStateException("Unable to acquire image"));
                    } else if (!completer2.set(acquireLatestImage)) {
                        acquireLatestImage.close();
                    }
                } catch (IllegalStateException e2) {
                    completer2.setException(e2);
                }
            }
        }, CameraXExecutors.mainThreadExecutor());
        final TakePictureState takePictureState = new TakePictureState();
        final FutureChain transformAsync = FutureChain.from(preTakePicture(takePictureState)).transformAsync(new AsyncFunction() { // from class: e.a.a.v
            @Override // androidx.camera.core.impl.utils.futures.AsyncFunction
            public final InterfaceFutureC2413a apply(Object obj) {
                return ImageCapture.this.issueTakePicture(imageCaptureRequest);
            }
        }, this.mExecutor);
        Futures.addCallback(transformAsync, new FutureCallback<Void>() { // from class: androidx.camera.core.ImageCapture.4
            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onFailure(Throwable th) {
                ImageCapture.this.postTakePicture(takePictureState);
                completer.setException(th);
            }

            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onSuccess(Void r2) {
                ImageCapture.this.postTakePicture(takePictureState);
            }
        }, this.mExecutor);
        completer.addCancellationListener(new Runnable() { // from class: e.a.a.a0
            @Override // java.lang.Runnable
            public final void run() {
                InterfaceFutureC2413a interfaceFutureC2413a = InterfaceFutureC2413a.this;
                int i2 = ImageCapture.ERROR_UNKNOWN;
                interfaceFutureC2413a.cancel(true);
            }
        }, CameraXExecutors.directExecutor());
        return "takePictureInternal";
    }

    public void cancelAfAeTrigger(TakePictureState takePictureState) {
        if (takePictureState.mIsAfTriggered || takePictureState.mIsAePrecaptureTriggered) {
            getCameraControl().cancelAfAeTrigger(takePictureState.mIsAfTriggered, takePictureState.mIsAePrecaptureTriggered);
            takePictureState.mIsAfTriggered = false;
            takePictureState.mIsAePrecaptureTriggered = false;
        }
    }

    public InterfaceFutureC2413a<Boolean> check3AConverged(TakePictureState takePictureState) {
        return (this.mEnableCheck3AConverged || takePictureState.mIsAePrecaptureTriggered) ? this.mSessionCallbackChecker.checkCaptureResult(new CaptureCallbackChecker.CaptureResultChecker<Boolean>() { // from class: androidx.camera.core.ImageCapture.7
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // androidx.camera.core.ImageCapture.CaptureCallbackChecker.CaptureResultChecker
            public Boolean check(@NonNull CameraCaptureResult cameraCaptureResult) {
                if (Logger.isDebugEnabled(ImageCapture.TAG)) {
                    StringBuilder m586H = C1499a.m586H("checkCaptureResult, AE=");
                    m586H.append(cameraCaptureResult.getAeState());
                    m586H.append(" AF =");
                    m586H.append(cameraCaptureResult.getAfState());
                    m586H.append(" AWB=");
                    m586H.append(cameraCaptureResult.getAwbState());
                    Logger.m123d(ImageCapture.TAG, m586H.toString());
                }
                if (ImageCapture.this.is3AConverged(cameraCaptureResult)) {
                    return Boolean.TRUE;
                }
                return null;
            }
        }, CHECK_3A_TIMEOUT_IN_MS, Boolean.FALSE) : Futures.immediateFuture(Boolean.FALSE);
    }

    @UiThread
    public void clearPipeline() {
        Threads.checkMainThread();
        DeferrableSurface deferrableSurface = this.mDeferrableSurface;
        this.mDeferrableSurface = null;
        this.mImageReader = null;
        this.mProcessingImageReader = null;
        if (deferrableSurface != null) {
            deferrableSurface.close();
        }
    }

    @UiThread
    public SessionConfig.Builder createPipeline(@NonNull final String str, @NonNull final ImageCaptureConfig imageCaptureConfig, @NonNull final Size size) {
        Threads.checkMainThread();
        SessionConfig.Builder createFrom = SessionConfig.Builder.createFrom(imageCaptureConfig);
        createFrom.addRepeatingCameraCaptureCallback(this.mSessionCallbackChecker);
        if (imageCaptureConfig.getImageReaderProxyProvider() != null) {
            this.mImageReader = new SafeCloseImageReaderProxy(imageCaptureConfig.getImageReaderProxyProvider().newInstance(size.getWidth(), size.getHeight(), getImageFormat(), 2, 0L));
            this.mMetadataMatchingCaptureCallback = new CameraCaptureCallback() { // from class: androidx.camera.core.ImageCapture.1
            };
        } else if (this.mCaptureProcessor != null) {
            ProcessingImageReader processingImageReader = new ProcessingImageReader(size.getWidth(), size.getHeight(), getImageFormat(), this.mMaxCaptureStages, this.mExecutor, getCaptureBundle(CaptureBundles.singleDefaultCaptureBundle()), this.mCaptureProcessor);
            this.mProcessingImageReader = processingImageReader;
            this.mMetadataMatchingCaptureCallback = processingImageReader.getCameraCaptureCallback();
            this.mImageReader = new SafeCloseImageReaderProxy(this.mProcessingImageReader);
        } else {
            MetadataImageReader metadataImageReader = new MetadataImageReader(size.getWidth(), size.getHeight(), getImageFormat(), 2);
            this.mMetadataMatchingCaptureCallback = metadataImageReader.getCameraCaptureCallback();
            this.mImageReader = new SafeCloseImageReaderProxy(metadataImageReader);
        }
        this.mImageCaptureRequestProcessor = new ImageCaptureRequestProcessor(2, new ImageCaptureRequestProcessor.ImageCaptor() { // from class: e.a.a.j0
            @Override // androidx.camera.core.ImageCapture.ImageCaptureRequestProcessor.ImageCaptor
            public final InterfaceFutureC2413a capture(ImageCapture.ImageCaptureRequest imageCaptureRequest) {
                return ImageCapture.this.m119a(imageCaptureRequest);
            }
        });
        this.mImageReader.setOnImageAvailableListener(this.mClosingListener, CameraXExecutors.mainThreadExecutor());
        SafeCloseImageReaderProxy safeCloseImageReaderProxy = this.mImageReader;
        DeferrableSurface deferrableSurface = this.mDeferrableSurface;
        if (deferrableSurface != null) {
            deferrableSurface.close();
        }
        ImmediateSurface immediateSurface = new ImmediateSurface(this.mImageReader.getSurface());
        this.mDeferrableSurface = immediateSurface;
        InterfaceFutureC2413a<Void> terminationFuture = immediateSurface.getTerminationFuture();
        Objects.requireNonNull(safeCloseImageReaderProxy);
        terminationFuture.addListener(new RunnableC4255s1(safeCloseImageReaderProxy), CameraXExecutors.mainThreadExecutor());
        createFrom.addNonRepeatingSurface(this.mDeferrableSurface);
        createFrom.addErrorListener(new SessionConfig.ErrorListener() { // from class: e.a.a.n0
            @Override // androidx.camera.core.impl.SessionConfig.ErrorListener
            public final void onError(SessionConfig sessionConfig, SessionConfig.SessionError sessionError) {
                ImageCapture imageCapture = ImageCapture.this;
                String str2 = str;
                ImageCaptureConfig imageCaptureConfig2 = imageCaptureConfig;
                Size size2 = size;
                imageCapture.clearPipeline();
                if (imageCapture.isCurrentCamera(str2)) {
                    SessionConfig.Builder createPipeline = imageCapture.createPipeline(str2, imageCaptureConfig2, size2);
                    imageCapture.mSessionConfigBuilder = createPipeline;
                    imageCapture.updateSessionConfig(createPipeline.build());
                    imageCapture.notifyReset();
                }
            }
        });
        return createFrom;
    }

    public int getCaptureMode() {
        return this.mCaptureMode;
    }

    /* JADX WARN: Type inference failed for: r2v2, types: [androidx.camera.core.impl.UseCaseConfig, androidx.camera.core.impl.UseCaseConfig<?>] */
    @Override // androidx.camera.core.UseCase
    @Nullable
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public UseCaseConfig<?> getDefaultConfig(boolean z, @NonNull UseCaseConfigFactory useCaseConfigFactory) {
        Config config = useCaseConfigFactory.getConfig(UseCaseConfigFactory.CaptureType.IMAGE_CAPTURE);
        if (z) {
            config = C4277q.m4852a(config, DEFAULT_CONFIG.getConfig());
        }
        if (config == null) {
            return null;
        }
        return getUseCaseConfigBuilder(config).getUseCaseConfig();
    }

    public int getFlashMode() {
        int i2;
        synchronized (this.mLockedFlashMode) {
            i2 = this.mFlashMode;
            if (i2 == -1) {
                i2 = ((ImageCaptureConfig) getCurrentConfig()).getFlashMode(2);
            }
        }
        return i2;
    }

    public int getTargetRotation() {
        return getTargetRotationInternal();
    }

    @Override // androidx.camera.core.UseCase
    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public UseCaseConfig.Builder<?, ?, ?> getUseCaseConfigBuilder(@NonNull Config config) {
        return Builder.fromConfig(config);
    }

    public boolean is3AConverged(CameraCaptureResult cameraCaptureResult) {
        if (cameraCaptureResult == null) {
            return false;
        }
        return (cameraCaptureResult.getAfMode() == CameraCaptureMetaData.AfMode.ON_CONTINUOUS_AUTO || cameraCaptureResult.getAfMode() == CameraCaptureMetaData.AfMode.OFF || cameraCaptureResult.getAfMode() == CameraCaptureMetaData.AfMode.UNKNOWN || cameraCaptureResult.getAfState() == CameraCaptureMetaData.AfState.FOCUSED || cameraCaptureResult.getAfState() == CameraCaptureMetaData.AfState.LOCKED_FOCUSED || cameraCaptureResult.getAfState() == CameraCaptureMetaData.AfState.LOCKED_NOT_FOCUSED) && (cameraCaptureResult.getAeState() == CameraCaptureMetaData.AeState.CONVERGED || cameraCaptureResult.getAeState() == CameraCaptureMetaData.AeState.FLASH_REQUIRED || cameraCaptureResult.getAeState() == CameraCaptureMetaData.AeState.UNKNOWN) && (cameraCaptureResult.getAwbState() == CameraCaptureMetaData.AwbState.CONVERGED || cameraCaptureResult.getAwbState() == CameraCaptureMetaData.AwbState.UNKNOWN);
    }

    public boolean isAePrecaptureRequired(TakePictureState takePictureState) {
        int flashMode = getFlashMode();
        if (flashMode == 0) {
            return takePictureState.mPreCaptureState.getAeState() == CameraCaptureMetaData.AeState.FLASH_REQUIRED;
        }
        if (flashMode == 1) {
            return true;
        }
        if (flashMode == 2) {
            return false;
        }
        throw new AssertionError(getFlashMode());
    }

    public InterfaceFutureC2413a<Void> issueTakePicture(@NonNull ImageCaptureRequest imageCaptureRequest) {
        CaptureBundle captureBundle;
        Logger.m123d(TAG, "issueTakePicture");
        ArrayList arrayList = new ArrayList();
        final ArrayList arrayList2 = new ArrayList();
        String str = null;
        if (this.mProcessingImageReader != null) {
            captureBundle = getCaptureBundle(null);
            if (captureBundle == null) {
                return Futures.immediateFailedFuture(new IllegalArgumentException("ImageCapture cannot set empty CaptureBundle."));
            }
            if (captureBundle.getCaptureStages().size() > this.mMaxCaptureStages) {
                return Futures.immediateFailedFuture(new IllegalArgumentException("ImageCapture has CaptureStages > Max CaptureStage size"));
            }
            this.mProcessingImageReader.setCaptureBundle(captureBundle);
            str = this.mProcessingImageReader.getTagBundleKey();
        } else {
            captureBundle = getCaptureBundle(CaptureBundles.singleDefaultCaptureBundle());
            if (captureBundle.getCaptureStages().size() > 1) {
                return Futures.immediateFailedFuture(new IllegalArgumentException("ImageCapture have no CaptureProcess set with CaptureBundle size > 1."));
            }
        }
        for (final CaptureStage captureStage : captureBundle.getCaptureStages()) {
            final CaptureConfig.Builder builder = new CaptureConfig.Builder();
            builder.setTemplateType(this.mCaptureConfig.getTemplateType());
            builder.addImplementationOptions(this.mCaptureConfig.getImplementationOptions());
            builder.addAllCameraCaptureCallbacks(this.mSessionConfigBuilder.getSingleCameraCaptureCallbacks());
            builder.addSurface(this.mDeferrableSurface);
            builder.addImplementationOption(CaptureConfig.OPTION_ROTATION, Integer.valueOf(imageCaptureRequest.mRotationDegrees));
            builder.addImplementationOption(CaptureConfig.OPTION_JPEG_QUALITY, Integer.valueOf(imageCaptureRequest.mJpegQuality));
            builder.addImplementationOptions(captureStage.getCaptureConfig().getImplementationOptions());
            if (str != null) {
                builder.addTag(str, Integer.valueOf(captureStage.getId()));
            }
            builder.addCameraCaptureCallback(this.mMetadataMatchingCaptureCallback);
            arrayList.add(CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.g0
                @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
                public final Object attachCompleter(final CallbackToFutureAdapter.Completer completer) {
                    final ImageCapture imageCapture = ImageCapture.this;
                    CaptureConfig.Builder builder2 = builder;
                    List list = arrayList2;
                    CaptureStage captureStage2 = captureStage;
                    Objects.requireNonNull(imageCapture);
                    builder2.addCameraCaptureCallback(new CameraCaptureCallback() { // from class: androidx.camera.core.ImageCapture.8
                        @Override // androidx.camera.core.impl.CameraCaptureCallback
                        public void onCaptureCancelled() {
                            completer.setException(new CameraClosedException("Capture request is cancelled because camera is closed"));
                        }

                        @Override // androidx.camera.core.impl.CameraCaptureCallback
                        public void onCaptureCompleted(@NonNull CameraCaptureResult cameraCaptureResult) {
                            completer.set(null);
                        }

                        @Override // androidx.camera.core.impl.CameraCaptureCallback
                        public void onCaptureFailed(@NonNull CameraCaptureFailure cameraCaptureFailure) {
                            StringBuilder m586H = C1499a.m586H("Capture request failed with reason ");
                            m586H.append(cameraCaptureFailure.getReason());
                            completer.setException(new CaptureFailedException(m586H.toString()));
                        }
                    });
                    list.add(builder2.build());
                    return "issueTakePicture[stage=" + captureStage2.getId() + "]";
                }
            }));
        }
        getCameraControl().submitCaptureRequests(arrayList2);
        return Futures.transform(Futures.allAsList(arrayList), new Function() { // from class: e.a.a.e0
            @Override // androidx.arch.core.util.Function
            public final Object apply(Object obj) {
                int i2 = ImageCapture.ERROR_UNKNOWN;
                return null;
            }
        }, CameraXExecutors.directExecutor());
    }

    @Override // androidx.camera.core.UseCase
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public void onAttached() {
        ImageCaptureConfig imageCaptureConfig = (ImageCaptureConfig) getCurrentConfig();
        this.mCaptureConfig = CaptureConfig.Builder.createFrom(imageCaptureConfig).build();
        this.mCaptureProcessor = imageCaptureConfig.getCaptureProcessor(null);
        this.mMaxCaptureStages = imageCaptureConfig.getMaxCaptureStages(2);
        this.mCaptureBundle = imageCaptureConfig.getCaptureBundle(CaptureBundles.singleDefaultCaptureBundle());
        this.mExecutor = Executors.newFixedThreadPool(1, new ThreadFactory() { // from class: androidx.camera.core.ImageCapture.5
            private final AtomicInteger mId = new AtomicInteger(0);

            @Override // java.util.concurrent.ThreadFactory
            public Thread newThread(@NonNull Runnable runnable) {
                StringBuilder m586H = C1499a.m586H("CameraX-image_capture_");
                m586H.append(this.mId.getAndIncrement());
                return new Thread(runnable, m586H.toString());
            }
        });
    }

    @Override // androidx.camera.core.UseCase
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public void onCameraControlReady() {
        trySetFlashModeToCameraControl();
    }

    @Override // androidx.camera.core.UseCase
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public void onDetached() {
        abortImageCaptureRequests();
        clearPipeline();
        this.mExecutor.shutdown();
    }

    /* JADX WARN: Type inference failed for: r7v1, types: [androidx.camera.core.impl.UseCaseConfig, androidx.camera.core.impl.UseCaseConfig<?>] */
    @Override // androidx.camera.core.UseCase
    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public UseCaseConfig<?> onMergeConfig(@NonNull UseCaseConfig.Builder<?, ?, ?> builder) {
        Integer num = (Integer) builder.getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_BUFFER_FORMAT, null);
        if (num != null) {
            Preconditions.checkArgument(builder.getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_CAPTURE_PROCESSOR, null) == null, "Cannot set buffer format with CaptureProcessor defined.");
            builder.getMutableConfig().insertOption(ImageInputConfig.OPTION_INPUT_FORMAT, num);
        } else if (builder.getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_CAPTURE_PROCESSOR, null) != null) {
            builder.getMutableConfig().insertOption(ImageInputConfig.OPTION_INPUT_FORMAT, 35);
        } else {
            builder.getMutableConfig().insertOption(ImageInputConfig.OPTION_INPUT_FORMAT, 256);
        }
        Preconditions.checkArgument(((Integer) builder.getMutableConfig().retrieveOption(ImageCaptureConfig.OPTION_MAX_CAPTURE_STAGES, 2)).intValue() >= 1, "Maximum outstanding image count must be at least 1");
        return builder.getUseCaseConfig();
    }

    @Override // androidx.camera.core.UseCase
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    @UiThread
    public void onStateDetached() {
        abortImageCaptureRequests();
    }

    @Override // androidx.camera.core.UseCase
    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public Size onSuggestedResolutionUpdated(@NonNull Size size) {
        SessionConfig.Builder createPipeline = createPipeline(getCameraId(), (ImageCaptureConfig) getCurrentConfig(), size);
        this.mSessionConfigBuilder = createPipeline;
        updateSessionConfig(createPipeline.build());
        notifyActive();
        return size;
    }

    public void postTakePicture(TakePictureState takePictureState) {
        cancelAfAeTrigger(takePictureState);
        unlockFlashMode();
    }

    public void setCropAspectRatio(@NonNull Rational rational) {
        this.mCropAspectRatio = rational;
    }

    public void setFlashMode(int i2) {
        if (i2 != 0 && i2 != 1 && i2 != 2) {
            throw new IllegalArgumentException(C1499a.m626l("Invalid flash mode: ", i2));
        }
        synchronized (this.mLockedFlashMode) {
            this.mFlashMode = i2;
            trySetFlashModeToCameraControl();
        }
    }

    public void setTargetRotation(int i2) {
        int targetRotation = getTargetRotation();
        if (!setTargetRotationInternal(i2) || this.mCropAspectRatio == null) {
            return;
        }
        this.mCropAspectRatio = ImageUtil.getRotatedAspectRatio(Math.abs(CameraOrientationUtil.surfaceRotationToDegrees(i2) - CameraOrientationUtil.surfaceRotationToDegrees(targetRotation)), this.mCropAspectRatio);
    }

    public void takePicture(@NonNull final Executor executor, @NonNull final OnImageCapturedCallback onImageCapturedCallback) {
        if (Looper.getMainLooper() != Looper.myLooper()) {
            CameraXExecutors.mainThreadExecutor().execute(new Runnable() { // from class: e.a.a.w
                @Override // java.lang.Runnable
                public final void run() {
                    ImageCapture.this.takePicture(executor, onImageCapturedCallback);
                }
            });
        } else {
            sendImageCaptureRequest(executor, onImageCapturedCallback);
        }
    }

    @NonNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("ImageCapture:");
        m586H.append(getName());
        return m586H.toString();
    }

    public InterfaceFutureC2413a<CameraCaptureResult> triggerAePrecapture(TakePictureState takePictureState) {
        Logger.m123d(TAG, "triggerAePrecapture");
        takePictureState.mIsAePrecaptureTriggered = true;
        return getCameraControl().triggerAePrecapture();
    }

    public void triggerAfIfNeeded(TakePictureState takePictureState) {
        if (this.mEnableCheck3AConverged && takePictureState.mPreCaptureState.getAfMode() == CameraCaptureMetaData.AfMode.ON_MANUAL_AUTO && takePictureState.mPreCaptureState.getAfState() == CameraCaptureMetaData.AfState.INACTIVE) {
            triggerAf(takePictureState);
        }
    }

    public void takePicture(@NonNull final OutputFileOptions outputFileOptions, @NonNull final Executor executor, @NonNull final OnImageSavedCallback onImageSavedCallback) {
        if (Looper.getMainLooper() != Looper.myLooper()) {
            CameraXExecutors.mainThreadExecutor().execute(new Runnable() { // from class: e.a.a.i0
                @Override // java.lang.Runnable
                public final void run() {
                    ImageCapture.this.takePicture(outputFileOptions, executor, onImageSavedCallback);
                }
            });
        } else {
            if (!ImageSaveLocationValidator.isValid(outputFileOptions)) {
                executor.execute(new Runnable() { // from class: e.a.a.m0
                    @Override // java.lang.Runnable
                    public final void run() {
                        ImageCapture.OnImageSavedCallback onImageSavedCallback2 = ImageCapture.OnImageSavedCallback.this;
                        int i2 = ImageCapture.ERROR_UNKNOWN;
                        onImageSavedCallback2.onError(new ImageCaptureException(1, "Cannot save capture result to specified location", null));
                    }
                });
                return;
            }
            final ImageSaver.OnImageSavedCallback onImageSavedCallback2 = new ImageSaver.OnImageSavedCallback() { // from class: androidx.camera.core.ImageCapture.2
                @Override // androidx.camera.core.ImageSaver.OnImageSavedCallback
                public void onError(ImageSaver.SaveError saveError, String str, @Nullable Throwable th) {
                    onImageSavedCallback.onError(new ImageCaptureException(saveError.ordinal() != 0 ? 0 : 1, str, th));
                }

                @Override // androidx.camera.core.ImageSaver.OnImageSavedCallback
                public void onImageSaved(@NonNull OutputFileResults outputFileResults) {
                    onImageSavedCallback.onImageSaved(outputFileResults);
                }
            };
            sendImageCaptureRequest(CameraXExecutors.mainThreadExecutor(), new OnImageCapturedCallback() { // from class: androidx.camera.core.ImageCapture.3
                @Override // androidx.camera.core.ImageCapture.OnImageCapturedCallback
                public void onCaptureSuccess(@NonNull ImageProxy imageProxy) {
                    ImageCapture.this.mIoExecutor.execute(new ImageSaver(imageProxy, outputFileOptions, imageProxy.getImageInfo().getRotationDegrees(), executor, onImageSavedCallback2));
                }

                @Override // androidx.camera.core.ImageCapture.OnImageCapturedCallback
                public void onError(@NonNull ImageCaptureException imageCaptureException) {
                    onImageSavedCallback.onError(imageCaptureException);
                }
            });
        }
    }
}
