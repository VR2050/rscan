package androidx.camera.core;

import android.app.Application;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.Resources;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import androidx.annotation.GuardedBy;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.arch.core.util.Function;
import androidx.camera.core.CameraX;
import androidx.camera.core.CameraXConfig;
import androidx.camera.core.impl.CameraDeviceSurfaceManager;
import androidx.camera.core.impl.CameraFactory;
import androidx.camera.core.impl.CameraInternal;
import androidx.camera.core.impl.CameraRepository;
import androidx.camera.core.impl.CameraThreadConfig;
import androidx.camera.core.impl.CameraValidator;
import androidx.camera.core.impl.UseCaseConfigFactory;
import androidx.camera.core.impl.quirk.IncompleteCameraListQuirk;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.AsyncFunction;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.FutureChain;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.core.os.HandlerCompat;
import androidx.core.util.Preconditions;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

@MainThread
@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes.dex */
public final class CameraX {
    private static final long RETRY_SLEEP_MILLIS = 500;
    private static final String RETRY_TOKEN = "retry_token";
    private static final String TAG = "CameraX";
    private static final long WAIT_INITIALIZED_TIMEOUT_MILLIS = 3000;

    @GuardedBy("INSTANCE_LOCK")
    private static CameraXConfig.Provider sConfigProvider;

    @GuardedBy("INSTANCE_LOCK")
    public static CameraX sInstance;
    private Context mAppContext;
    private final Executor mCameraExecutor;
    private CameraFactory mCameraFactory;
    private final CameraXConfig mCameraXConfig;
    private UseCaseConfigFactory mDefaultConfigFactory;
    private final Handler mSchedulerHandler;

    @Nullable
    private final HandlerThread mSchedulerThread;
    private CameraDeviceSurfaceManager mSurfaceManager;
    public static final Object INSTANCE_LOCK = new Object();

    @GuardedBy("INSTANCE_LOCK")
    private static InterfaceFutureC2413a<Void> sInitializeFuture = Futures.immediateFailedFuture(new IllegalStateException("CameraX is not initialized."));

    @GuardedBy("INSTANCE_LOCK")
    private static InterfaceFutureC2413a<Void> sShutdownFuture = Futures.immediateFuture(null);
    public final CameraRepository mCameraRepository = new CameraRepository();
    private final Object mInitializeLock = new Object();

    @GuardedBy("mInitializeLock")
    private InternalInitState mInitState = InternalInitState.UNINITIALIZED;

    @GuardedBy("mInitializeLock")
    private InterfaceFutureC2413a<Void> mShutdownInternalFuture = Futures.immediateFuture(null);

    /* renamed from: androidx.camera.core.CameraX$2 */
    public static /* synthetic */ class C01452 {
        public static final /* synthetic */ int[] $SwitchMap$androidx$camera$core$CameraX$InternalInitState;

        static {
            InternalInitState.values();
            int[] iArr = new int[4];
            $SwitchMap$androidx$camera$core$CameraX$InternalInitState = iArr;
            try {
                iArr[InternalInitState.UNINITIALIZED.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$androidx$camera$core$CameraX$InternalInitState[InternalInitState.INITIALIZING.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$androidx$camera$core$CameraX$InternalInitState[InternalInitState.INITIALIZED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$androidx$camera$core$CameraX$InternalInitState[InternalInitState.SHUTDOWN.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    public enum InternalInitState {
        UNINITIALIZED,
        INITIALIZING,
        INITIALIZED,
        SHUTDOWN
    }

    public CameraX(@NonNull CameraXConfig cameraXConfig) {
        this.mCameraXConfig = (CameraXConfig) Preconditions.checkNotNull(cameraXConfig);
        Executor cameraExecutor = cameraXConfig.getCameraExecutor(null);
        Handler schedulerHandler = cameraXConfig.getSchedulerHandler(null);
        this.mCameraExecutor = cameraExecutor == null ? new CameraExecutor() : cameraExecutor;
        if (schedulerHandler != null) {
            this.mSchedulerThread = null;
            this.mSchedulerHandler = schedulerHandler;
        } else {
            HandlerThread handlerThread = new HandlerThread("CameraX-scheduler", 10);
            this.mSchedulerThread = handlerThread;
            handlerThread.start();
            this.mSchedulerHandler = HandlerCompat.createAsync(handlerThread.getLooper());
        }
    }

    @NonNull
    private static CameraX checkInitialized() {
        CameraX waitInitialized = waitInitialized();
        Preconditions.checkState(waitInitialized.isInitializedInternal(), "Must call CameraX.initialize() first");
        return waitInitialized;
    }

    public static void configureInstance(@NonNull final CameraXConfig cameraXConfig) {
        synchronized (INSTANCE_LOCK) {
            configureInstanceLocked(new CameraXConfig.Provider() { // from class: e.a.a.h
                @Override // androidx.camera.core.CameraXConfig.Provider
                public final CameraXConfig getCameraXConfig() {
                    CameraXConfig cameraXConfig2 = CameraXConfig.this;
                    Object obj = CameraX.INSTANCE_LOCK;
                    return cameraXConfig2;
                }
            });
        }
    }

    @GuardedBy("INSTANCE_LOCK")
    private static void configureInstanceLocked(@NonNull CameraXConfig.Provider provider) {
        Preconditions.checkNotNull(provider);
        Preconditions.checkState(sConfigProvider == null, "CameraX has already been configured. To use a different configuration, shutdown() must be called.");
        sConfigProvider = provider;
    }

    @Nullable
    private static Application getApplicationFromContext(@NonNull Context context) {
        for (Context applicationContext = context.getApplicationContext(); applicationContext instanceof ContextWrapper; applicationContext = ((ContextWrapper) applicationContext).getBaseContext()) {
            if (applicationContext instanceof Application) {
                return (Application) applicationContext;
            }
        }
        return null;
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public static CameraInternal getCameraWithCameraSelector(@NonNull CameraSelector cameraSelector) {
        return cameraSelector.select(checkInitialized().getCameraRepository().getCameras());
    }

    @Nullable
    private static CameraXConfig.Provider getConfigProvider(@NonNull Context context) {
        ComponentCallbacks2 applicationFromContext = getApplicationFromContext(context);
        if (applicationFromContext instanceof CameraXConfig.Provider) {
            return (CameraXConfig.Provider) applicationFromContext;
        }
        try {
            return (CameraXConfig.Provider) Class.forName(context.getApplicationContext().getResources().getString(C0168R.string.androidx_camera_default_config_provider)).getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
        } catch (Resources.NotFoundException | ClassNotFoundException | IllegalAccessException | InstantiationException | NoSuchMethodException | NullPointerException | InvocationTargetException e2) {
            Logger.m126e(TAG, "Failed to retrieve default CameraXConfig.Provider from resources", e2);
            return null;
        }
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    @Deprecated
    public static Context getContext() {
        return checkInitialized().mAppContext;
    }

    @NonNull
    private static InterfaceFutureC2413a<CameraX> getInstance() {
        InterfaceFutureC2413a<CameraX> instanceLocked;
        synchronized (INSTANCE_LOCK) {
            instanceLocked = getInstanceLocked();
        }
        return instanceLocked;
    }

    @NonNull
    @GuardedBy("INSTANCE_LOCK")
    private static InterfaceFutureC2413a<CameraX> getInstanceLocked() {
        final CameraX cameraX = sInstance;
        return cameraX == null ? Futures.immediateFailedFuture(new IllegalStateException("Must call CameraX.initialize() first")) : Futures.transform(sInitializeFuture, new Function() { // from class: e.a.a.e
            @Override // androidx.arch.core.util.Function
            public final Object apply(Object obj) {
                CameraX cameraX2 = CameraX.this;
                Object obj2 = CameraX.INSTANCE_LOCK;
                return cameraX2;
            }
        }, CameraXExecutors.directExecutor());
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public static InterfaceFutureC2413a<CameraX> getOrCreateInstance(@NonNull Context context) {
        InterfaceFutureC2413a<CameraX> instanceLocked;
        Preconditions.checkNotNull(context, "Context must not be null.");
        synchronized (INSTANCE_LOCK) {
            boolean z = sConfigProvider != null;
            instanceLocked = getInstanceLocked();
            if (instanceLocked.isDone()) {
                try {
                    instanceLocked.get();
                } catch (InterruptedException e2) {
                    throw new RuntimeException("Unexpected thread interrupt. Should not be possible since future is already complete.", e2);
                } catch (ExecutionException unused) {
                    shutdownLocked();
                    instanceLocked = null;
                }
            }
            if (instanceLocked == null) {
                if (!z) {
                    CameraXConfig.Provider configProvider = getConfigProvider(context);
                    if (configProvider == null) {
                        throw new IllegalStateException("CameraX is not configured properly. The most likely cause is you did not include a default implementation in your build such as 'camera-camera2'.");
                    }
                    configureInstanceLocked(configProvider);
                }
                initializeInstanceLocked(context);
                instanceLocked = getInstanceLocked();
            }
        }
        return instanceLocked;
    }

    private void initAndRetryRecursively(@NonNull final Executor executor, final long j2, @NonNull final Context context, @NonNull final CallbackToFutureAdapter.Completer<Void> completer) {
        executor.execute(new Runnable() { // from class: e.a.a.l
            @Override // java.lang.Runnable
            public final void run() {
                CameraX.this.m113b(context, executor, completer, j2);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public InterfaceFutureC2413a<Void> initInternal(@NonNull final Context context) {
        InterfaceFutureC2413a<Void> future;
        synchronized (this.mInitializeLock) {
            Preconditions.checkState(this.mInitState == InternalInitState.UNINITIALIZED, "CameraX.initInternal() should only be called once per instance");
            this.mInitState = InternalInitState.INITIALIZING;
            future = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.d
                @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
                public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                    CameraX.this.m114c(context, completer);
                    return "CameraX initInternal";
                }
            });
        }
        return future;
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.TESTS})
    public static InterfaceFutureC2413a<Void> initialize(@NonNull Context context, @NonNull final CameraXConfig cameraXConfig) {
        InterfaceFutureC2413a<Void> interfaceFutureC2413a;
        synchronized (INSTANCE_LOCK) {
            Preconditions.checkNotNull(context);
            configureInstanceLocked(new CameraXConfig.Provider() { // from class: e.a.a.i
                @Override // androidx.camera.core.CameraXConfig.Provider
                public final CameraXConfig getCameraXConfig() {
                    CameraXConfig cameraXConfig2 = CameraXConfig.this;
                    Object obj = CameraX.INSTANCE_LOCK;
                    return cameraXConfig2;
                }
            });
            initializeInstanceLocked(context);
            interfaceFutureC2413a = sInitializeFuture;
        }
        return interfaceFutureC2413a;
    }

    @GuardedBy("INSTANCE_LOCK")
    private static void initializeInstanceLocked(@NonNull final Context context) {
        Preconditions.checkNotNull(context);
        Preconditions.checkState(sInstance == null, "CameraX already initialized.");
        Preconditions.checkNotNull(sConfigProvider);
        final CameraX cameraX = new CameraX(sConfigProvider.getCameraXConfig());
        sInstance = cameraX;
        sInitializeFuture = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.f
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                CameraX.lambda$initializeInstanceLocked$3(CameraX.this, context, completer);
                return "CameraX-initialize";
            }
        });
    }

    @RestrictTo({RestrictTo.Scope.TESTS})
    public static boolean isInitialized() {
        boolean z;
        synchronized (INSTANCE_LOCK) {
            CameraX cameraX = sInstance;
            z = cameraX != null && cameraX.isInitializedInternal();
        }
        return z;
    }

    private boolean isInitializedInternal() {
        boolean z;
        synchronized (this.mInitializeLock) {
            z = this.mInitState == InternalInitState.INITIALIZED;
        }
        return z;
    }

    public static /* synthetic */ Object lambda$initializeInstanceLocked$3(final CameraX cameraX, final Context context, final CallbackToFutureAdapter.Completer completer) {
        synchronized (INSTANCE_LOCK) {
            Futures.addCallback(FutureChain.from(sShutdownFuture).transformAsync(new AsyncFunction() { // from class: e.a.a.j
                @Override // androidx.camera.core.impl.utils.futures.AsyncFunction
                public final InterfaceFutureC2413a apply(Object obj) {
                    InterfaceFutureC2413a initInternal;
                    initInternal = CameraX.this.initInternal(context);
                    return initInternal;
                }
            }, CameraXExecutors.directExecutor()), new FutureCallback<Void>() { // from class: androidx.camera.core.CameraX.1
                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onFailure(Throwable th) {
                    Logger.m130w(CameraX.TAG, "CameraX initialize() failed", th);
                    synchronized (CameraX.INSTANCE_LOCK) {
                        if (CameraX.sInstance == cameraX) {
                            CameraX.shutdownLocked();
                        }
                    }
                    CallbackToFutureAdapter.Completer.this.setException(th);
                }

                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onSuccess(@Nullable Void r2) {
                    CallbackToFutureAdapter.Completer.this.set(null);
                }
            }, CameraXExecutors.directExecutor());
        }
        return "CameraX-initialize";
    }

    public static /* synthetic */ Object lambda$shutdownLocked$5(final CameraX cameraX, final CallbackToFutureAdapter.Completer completer) {
        synchronized (INSTANCE_LOCK) {
            sInitializeFuture.addListener(new Runnable() { // from class: e.a.a.m
                @Override // java.lang.Runnable
                public final void run() {
                    Futures.propagate(CameraX.this.shutdownInternal(), completer);
                }
            }, CameraXExecutors.directExecutor());
        }
        return "CameraX shutdown";
    }

    private void setStateToInitialized() {
        synchronized (this.mInitializeLock) {
            this.mInitState = InternalInitState.INITIALIZED;
        }
    }

    @NonNull
    public static InterfaceFutureC2413a<Void> shutdown() {
        InterfaceFutureC2413a<Void> shutdownLocked;
        synchronized (INSTANCE_LOCK) {
            sConfigProvider = null;
            shutdownLocked = shutdownLocked();
        }
        return shutdownLocked;
    }

    @NonNull
    private InterfaceFutureC2413a<Void> shutdownInternal() {
        synchronized (this.mInitializeLock) {
            this.mSchedulerHandler.removeCallbacksAndMessages(RETRY_TOKEN);
            int ordinal = this.mInitState.ordinal();
            if (ordinal == 0) {
                this.mInitState = InternalInitState.SHUTDOWN;
                return Futures.immediateFuture(null);
            }
            if (ordinal == 1) {
                throw new IllegalStateException("CameraX could not be shutdown when it is initializing.");
            }
            if (ordinal == 2) {
                this.mInitState = InternalInitState.SHUTDOWN;
                this.mShutdownInternalFuture = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.o
                    @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
                    public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                        CameraX.this.m116e(completer);
                        return "CameraX shutdownInternal";
                    }
                });
            }
            return this.mShutdownInternalFuture;
        }
    }

    @NonNull
    @GuardedBy("INSTANCE_LOCK")
    public static InterfaceFutureC2413a<Void> shutdownLocked() {
        final CameraX cameraX = sInstance;
        if (cameraX == null) {
            return sShutdownFuture;
        }
        sInstance = null;
        InterfaceFutureC2413a<Void> future = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.n
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                CameraX.lambda$shutdownLocked$5(CameraX.this, completer);
                return "CameraX shutdown";
            }
        });
        sShutdownFuture = future;
        return future;
    }

    @NonNull
    private static CameraX waitInitialized() {
        try {
            return getInstance().get(WAIT_INITIALIZED_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e2) {
            throw new IllegalStateException(e2);
        }
    }

    /* renamed from: a */
    public /* synthetic */ void m112a(Executor executor, long j2, CallbackToFutureAdapter.Completer completer) {
        initAndRetryRecursively(executor, j2, this.mAppContext, completer);
    }

    /* renamed from: b */
    public /* synthetic */ void m113b(Context context, final Executor executor, final CallbackToFutureAdapter.Completer completer, final long j2) {
        try {
            Application applicationFromContext = getApplicationFromContext(context);
            this.mAppContext = applicationFromContext;
            if (applicationFromContext == null) {
                this.mAppContext = context.getApplicationContext();
            }
            CameraFactory.Provider cameraFactoryProvider = this.mCameraXConfig.getCameraFactoryProvider(null);
            if (cameraFactoryProvider == null) {
                throw new InitializationException(new IllegalArgumentException("Invalid app configuration provided. Missing CameraFactory."));
            }
            this.mCameraFactory = cameraFactoryProvider.newInstance(this.mAppContext, CameraThreadConfig.create(this.mCameraExecutor, this.mSchedulerHandler));
            CameraDeviceSurfaceManager.Provider deviceSurfaceManagerProvider = this.mCameraXConfig.getDeviceSurfaceManagerProvider(null);
            if (deviceSurfaceManagerProvider == null) {
                throw new InitializationException(new IllegalArgumentException("Invalid app configuration provided. Missing CameraDeviceSurfaceManager."));
            }
            this.mSurfaceManager = deviceSurfaceManagerProvider.newInstance(this.mAppContext, this.mCameraFactory.getCameraManager());
            UseCaseConfigFactory.Provider useCaseConfigFactoryProvider = this.mCameraXConfig.getUseCaseConfigFactoryProvider(null);
            if (useCaseConfigFactoryProvider == null) {
                throw new InitializationException(new IllegalArgumentException("Invalid app configuration provided. Missing UseCaseConfigFactory."));
            }
            this.mDefaultConfigFactory = useCaseConfigFactoryProvider.newInstance(this.mAppContext);
            if (executor instanceof CameraExecutor) {
                ((CameraExecutor) executor).init(this.mCameraFactory);
            }
            this.mCameraRepository.init(this.mCameraFactory);
            if (IncompleteCameraListQuirk.isCurrentDeviceAffected()) {
                CameraValidator.validateCameras(this.mAppContext, this.mCameraRepository);
            }
            setStateToInitialized();
            completer.set(null);
        } catch (InitializationException | CameraValidator.CameraIdListIncorrectException | RuntimeException e2) {
            if (SystemClock.elapsedRealtime() - j2 < 2500) {
                Logger.m130w(TAG, "Retry init. Start time " + j2 + " current time " + SystemClock.elapsedRealtime(), e2);
                HandlerCompat.postDelayed(this.mSchedulerHandler, new Runnable() { // from class: e.a.a.g
                    @Override // java.lang.Runnable
                    public final void run() {
                        CameraX.this.m112a(executor, j2, completer);
                    }
                }, RETRY_TOKEN, RETRY_SLEEP_MILLIS);
                return;
            }
            setStateToInitialized();
            if (e2 instanceof CameraValidator.CameraIdListIncorrectException) {
                Logger.m125e(TAG, "The device might underreport the amount of the cameras. Finish the initialize task since we are already reaching the maximum number of retries.");
                completer.set(null);
            } else if (e2 instanceof InitializationException) {
                completer.setException(e2);
            } else {
                completer.setException(new InitializationException(e2));
            }
        }
    }

    /* renamed from: c */
    public /* synthetic */ Object m114c(Context context, CallbackToFutureAdapter.Completer completer) {
        initAndRetryRecursively(this.mCameraExecutor, SystemClock.elapsedRealtime(), context, completer);
        return "CameraX initInternal";
    }

    /* renamed from: d */
    public /* synthetic */ void m115d(CallbackToFutureAdapter.Completer completer) {
        if (this.mSchedulerThread != null) {
            Executor executor = this.mCameraExecutor;
            if (executor instanceof CameraExecutor) {
                ((CameraExecutor) executor).deinit();
            }
            this.mSchedulerThread.quit();
            completer.set(null);
        }
    }

    /* renamed from: e */
    public /* synthetic */ Object m116e(final CallbackToFutureAdapter.Completer completer) {
        this.mCameraRepository.deinit().addListener(new Runnable() { // from class: e.a.a.k
            @Override // java.lang.Runnable
            public final void run() {
                CameraX.this.m115d(completer);
            }
        }, this.mCameraExecutor);
        return "CameraX shutdownInternal";
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public CameraDeviceSurfaceManager getCameraDeviceSurfaceManager() {
        CameraDeviceSurfaceManager cameraDeviceSurfaceManager = this.mSurfaceManager;
        if (cameraDeviceSurfaceManager != null) {
            return cameraDeviceSurfaceManager;
        }
        throw new IllegalStateException("CameraX not initialized yet.");
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public CameraFactory getCameraFactory() {
        CameraFactory cameraFactory = this.mCameraFactory;
        if (cameraFactory != null) {
            return cameraFactory;
        }
        throw new IllegalStateException("CameraX not initialized yet.");
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public CameraRepository getCameraRepository() {
        return this.mCameraRepository;
    }

    @NonNull
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public UseCaseConfigFactory getDefaultConfigFactory() {
        UseCaseConfigFactory useCaseConfigFactory = this.mDefaultConfigFactory;
        if (useCaseConfigFactory != null) {
            return useCaseConfigFactory;
        }
        throw new IllegalStateException("CameraX not initialized yet.");
    }
}
