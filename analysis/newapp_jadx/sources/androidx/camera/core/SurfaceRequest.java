package androidx.camera.core;

import android.annotation.SuppressLint;
import android.graphics.Rect;
import android.util.Size;
import android.view.Surface;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.camera.core.SurfaceRequest;
import androidx.camera.core.impl.CameraInternal;
import androidx.camera.core.impl.DeferrableSurface;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.core.util.Consumer;
import androidx.core.util.Preconditions;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public final class SurfaceRequest {
    private final CameraInternal mCamera;
    private final DeferrableSurface mInternalDeferrableSurface;
    private final boolean mRGBA8888Required;
    private final CallbackToFutureAdapter.Completer<Void> mRequestCancellationCompleter;
    private final Size mResolution;
    private final InterfaceFutureC2413a<Void> mSessionStatusFuture;
    private final CallbackToFutureAdapter.Completer<Surface> mSurfaceCompleter;
    public final InterfaceFutureC2413a<Surface> mSurfaceFuture;

    @Nullable
    private TransformationInfo mTransformationInfo;

    @Nullable
    private Executor mTransformationInfoExecutor;

    @Nullable
    private TransformationInfoListener mTransformationInfoListener;

    public static final class RequestCancelledException extends RuntimeException {
        public RequestCancelledException(@NonNull String str, @NonNull Throwable th) {
            super(str, th);
        }
    }

    public static abstract class Result {
        public static final int RESULT_INVALID_SURFACE = 2;
        public static final int RESULT_REQUEST_CANCELLED = 1;
        public static final int RESULT_SURFACE_ALREADY_PROVIDED = 3;
        public static final int RESULT_SURFACE_USED_SUCCESSFULLY = 0;
        public static final int RESULT_WILL_NOT_PROVIDE_SURFACE = 4;

        @Retention(RetentionPolicy.SOURCE)
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public @interface ResultCode {
        }

        @NonNull
        /* renamed from: of */
        public static Result m133of(int i2, @NonNull Surface surface) {
            return new AutoValue_SurfaceRequest_Result(i2, surface);
        }

        public abstract int getResultCode();

        @NonNull
        public abstract Surface getSurface();
    }

    @ExperimentalUseCaseGroup
    public static abstract class TransformationInfo {
        @NonNull
        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        /* renamed from: of */
        public static TransformationInfo m134of(@NonNull Rect rect, int i2, int i3) {
            return new AutoValue_SurfaceRequest_TransformationInfo(rect, i2, i3);
        }

        @NonNull
        public abstract Rect getCropRect();

        public abstract int getRotationDegrees();

        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        public abstract int getTargetRotation();
    }

    @ExperimentalUseCaseGroup
    public interface TransformationInfoListener {
        void onTransformationInfoUpdate(@NonNull TransformationInfo transformationInfo);
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public SurfaceRequest(@NonNull Size size, @NonNull CameraInternal cameraInternal, boolean z) {
        this.mResolution = size;
        this.mCamera = cameraInternal;
        this.mRGBA8888Required = z;
        final String str = "SurfaceRequest[size: " + size + ", id: " + hashCode() + "]";
        final AtomicReference atomicReference = new AtomicReference(null);
        final InterfaceFutureC2413a future = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.g1
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                AtomicReference atomicReference2 = atomicReference;
                String str2 = str;
                atomicReference2.set(completer);
                return str2 + "-cancellation";
            }
        });
        final CallbackToFutureAdapter.Completer<Void> completer = (CallbackToFutureAdapter.Completer) Preconditions.checkNotNull((CallbackToFutureAdapter.Completer) atomicReference.get());
        this.mRequestCancellationCompleter = completer;
        final AtomicReference atomicReference2 = new AtomicReference(null);
        InterfaceFutureC2413a<Void> future2 = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.h1
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(CallbackToFutureAdapter.Completer completer2) {
                AtomicReference atomicReference3 = atomicReference2;
                String str2 = str;
                atomicReference3.set(completer2);
                return str2 + "-status";
            }
        });
        this.mSessionStatusFuture = future2;
        Futures.addCallback(future2, new FutureCallback<Void>() { // from class: androidx.camera.core.SurfaceRequest.1
            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onFailure(Throwable th) {
                if (th instanceof RequestCancelledException) {
                    Preconditions.checkState(future.cancel(false));
                } else {
                    Preconditions.checkState(completer.set(null));
                }
            }

            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onSuccess(@Nullable Void r2) {
                Preconditions.checkState(completer.set(null));
            }
        }, CameraXExecutors.directExecutor());
        final CallbackToFutureAdapter.Completer completer2 = (CallbackToFutureAdapter.Completer) Preconditions.checkNotNull((CallbackToFutureAdapter.Completer) atomicReference2.get());
        final AtomicReference atomicReference3 = new AtomicReference(null);
        InterfaceFutureC2413a<Surface> future3 = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.f1
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(CallbackToFutureAdapter.Completer completer3) {
                AtomicReference atomicReference4 = atomicReference3;
                String str2 = str;
                atomicReference4.set(completer3);
                return str2 + "-Surface";
            }
        });
        this.mSurfaceFuture = future3;
        this.mSurfaceCompleter = (CallbackToFutureAdapter.Completer) Preconditions.checkNotNull((CallbackToFutureAdapter.Completer) atomicReference3.get());
        DeferrableSurface deferrableSurface = new DeferrableSurface() { // from class: androidx.camera.core.SurfaceRequest.2
            @Override // androidx.camera.core.impl.DeferrableSurface
            @NonNull
            public InterfaceFutureC2413a<Surface> provideSurface() {
                return SurfaceRequest.this.mSurfaceFuture;
            }
        };
        this.mInternalDeferrableSurface = deferrableSurface;
        final InterfaceFutureC2413a<Void> terminationFuture = deferrableSurface.getTerminationFuture();
        Futures.addCallback(future3, new FutureCallback<Surface>() { // from class: androidx.camera.core.SurfaceRequest.3
            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onFailure(Throwable th) {
                if (th instanceof CancellationException) {
                    Preconditions.checkState(completer2.setException(new RequestCancelledException(C1499a.m582D(new StringBuilder(), str, " cancelled."), th)));
                } else {
                    completer2.set(null);
                }
            }

            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onSuccess(@Nullable Surface surface) {
                Futures.propagate(terminationFuture, completer2);
            }
        }, CameraXExecutors.directExecutor());
        terminationFuture.addListener(new Runnable() { // from class: e.a.a.e1
            @Override // java.lang.Runnable
            public final void run() {
                SurfaceRequest.this.mSurfaceFuture.cancel(true);
            }
        }, CameraXExecutors.directExecutor());
    }

    @SuppressLint({"PairedRegistration"})
    public void addRequestCancellationListener(@NonNull Executor executor, @NonNull Runnable runnable) {
        this.mRequestCancellationCompleter.addCancellationListener(runnable, executor);
    }

    @ExperimentalUseCaseGroup
    public void clearTransformationInfoListener() {
        this.mTransformationInfoListener = null;
        this.mTransformationInfoExecutor = null;
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public CameraInternal getCamera() {
        return this.mCamera;
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public DeferrableSurface getDeferrableSurface() {
        return this.mInternalDeferrableSurface;
    }

    @NonNull
    public Size getResolution() {
        return this.mResolution;
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public boolean isRGBA8888Required() {
        return this.mRGBA8888Required;
    }

    public void provideSurface(@NonNull final Surface surface, @NonNull Executor executor, @NonNull final Consumer<Result> consumer) {
        if (this.mSurfaceCompleter.set(surface) || this.mSurfaceFuture.isCancelled()) {
            Futures.addCallback(this.mSessionStatusFuture, new FutureCallback<Void>() { // from class: androidx.camera.core.SurfaceRequest.4
                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onFailure(Throwable th) {
                    Preconditions.checkState(th instanceof RequestCancelledException, "Camera surface session should only fail with request cancellation. Instead failed due to:\n" + th);
                    consumer.accept(Result.m133of(1, surface));
                }

                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onSuccess(@Nullable Void r3) {
                    consumer.accept(Result.m133of(0, surface));
                }
            }, executor);
            return;
        }
        Preconditions.checkState(this.mSurfaceFuture.isDone());
        try {
            this.mSurfaceFuture.get();
            executor.execute(new Runnable() { // from class: e.a.a.a1
                @Override // java.lang.Runnable
                public final void run() {
                    Consumer.this.accept(SurfaceRequest.Result.m133of(3, surface));
                }
            });
        } catch (InterruptedException | ExecutionException unused) {
            executor.execute(new Runnable() { // from class: e.a.a.b1
                @Override // java.lang.Runnable
                public final void run() {
                    Consumer.this.accept(SurfaceRequest.Result.m133of(4, surface));
                }
            });
        }
    }

    @ExperimentalUseCaseGroup
    public void setTransformationInfoListener(@NonNull Executor executor, @NonNull final TransformationInfoListener transformationInfoListener) {
        this.mTransformationInfoListener = transformationInfoListener;
        this.mTransformationInfoExecutor = executor;
        final TransformationInfo transformationInfo = this.mTransformationInfo;
        if (transformationInfo != null) {
            executor.execute(new Runnable() { // from class: e.a.a.c1
                @Override // java.lang.Runnable
                public final void run() {
                    SurfaceRequest.TransformationInfoListener.this.onTransformationInfoUpdate(transformationInfo);
                }
            });
        }
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    @ExperimentalUseCaseGroup
    public void updateTransformationInfo(@NonNull final TransformationInfo transformationInfo) {
        this.mTransformationInfo = transformationInfo;
        final TransformationInfoListener transformationInfoListener = this.mTransformationInfoListener;
        if (transformationInfoListener != null) {
            this.mTransformationInfoExecutor.execute(new Runnable() { // from class: e.a.a.d1
                @Override // java.lang.Runnable
                public final void run() {
                    SurfaceRequest.TransformationInfoListener.this.onTransformationInfoUpdate(transformationInfo);
                }
            });
        }
    }

    public boolean willNotProvideSurface() {
        return this.mSurfaceCompleter.setException(new DeferrableSurface.SurfaceUnavailableException("Surface request will not complete."));
    }
}
