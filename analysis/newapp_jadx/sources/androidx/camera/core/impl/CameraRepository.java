package androidx.camera.core.impl;

import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.InitializationException;
import androidx.camera.core.Logger;
import androidx.camera.core.impl.CameraRepository;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.core.util.Preconditions;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public final class CameraRepository {
    private static final String TAG = "CameraRepository";

    @GuardedBy("mCamerasLock")
    private CallbackToFutureAdapter.Completer<Void> mDeinitCompleter;

    @GuardedBy("mCamerasLock")
    private InterfaceFutureC2413a<Void> mDeinitFuture;
    private final Object mCamerasLock = new Object();

    @GuardedBy("mCamerasLock")
    private final Map<String, CameraInternal> mCameras = new LinkedHashMap();

    @GuardedBy("mCamerasLock")
    private final Set<CameraInternal> mReleasingCameras = new HashSet();

    /* renamed from: a */
    public /* synthetic */ Object m137a(CallbackToFutureAdapter.Completer completer) {
        synchronized (this.mCamerasLock) {
            this.mDeinitCompleter = completer;
        }
        return "CameraRepository-deinit";
    }

    /* renamed from: b */
    public /* synthetic */ void m138b(CameraInternal cameraInternal) {
        synchronized (this.mCamerasLock) {
            this.mReleasingCameras.remove(cameraInternal);
            if (this.mReleasingCameras.isEmpty()) {
                Preconditions.checkNotNull(this.mDeinitCompleter);
                this.mDeinitCompleter.set(null);
                this.mDeinitCompleter = null;
                this.mDeinitFuture = null;
            }
        }
    }

    @NonNull
    public InterfaceFutureC2413a<Void> deinit() {
        synchronized (this.mCamerasLock) {
            if (this.mCameras.isEmpty()) {
                InterfaceFutureC2413a<Void> interfaceFutureC2413a = this.mDeinitFuture;
                if (interfaceFutureC2413a == null) {
                    interfaceFutureC2413a = Futures.immediateFuture(null);
                }
                return interfaceFutureC2413a;
            }
            InterfaceFutureC2413a<Void> interfaceFutureC2413a2 = this.mDeinitFuture;
            if (interfaceFutureC2413a2 == null) {
                interfaceFutureC2413a2 = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.u1.c
                    @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
                    public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                        CameraRepository.this.m137a(completer);
                        return "CameraRepository-deinit";
                    }
                });
                this.mDeinitFuture = interfaceFutureC2413a2;
            }
            this.mReleasingCameras.addAll(this.mCameras.values());
            for (final CameraInternal cameraInternal : this.mCameras.values()) {
                cameraInternal.release().addListener(new Runnable() { // from class: e.a.a.u1.d
                    @Override // java.lang.Runnable
                    public final void run() {
                        CameraRepository.this.m138b(cameraInternal);
                    }
                }, CameraXExecutors.directExecutor());
            }
            this.mCameras.clear();
            return interfaceFutureC2413a2;
        }
    }

    @NonNull
    public CameraInternal getCamera(@NonNull String str) {
        CameraInternal cameraInternal;
        synchronized (this.mCamerasLock) {
            cameraInternal = this.mCameras.get(str);
            if (cameraInternal == null) {
                throw new IllegalArgumentException("Invalid camera: " + str);
            }
        }
        return cameraInternal;
    }

    @NonNull
    public Set<String> getCameraIds() {
        LinkedHashSet linkedHashSet;
        synchronized (this.mCamerasLock) {
            linkedHashSet = new LinkedHashSet(this.mCameras.keySet());
        }
        return linkedHashSet;
    }

    @NonNull
    public LinkedHashSet<CameraInternal> getCameras() {
        LinkedHashSet<CameraInternal> linkedHashSet;
        synchronized (this.mCamerasLock) {
            linkedHashSet = new LinkedHashSet<>(this.mCameras.values());
        }
        return linkedHashSet;
    }

    public void init(@NonNull CameraFactory cameraFactory) {
        synchronized (this.mCamerasLock) {
            try {
                try {
                    for (String str : cameraFactory.getAvailableCameraIds()) {
                        Logger.m123d(TAG, "Added camera: " + str);
                        this.mCameras.put(str, cameraFactory.getCamera(str));
                    }
                } catch (CameraUnavailableException e2) {
                    throw new InitializationException(e2);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
