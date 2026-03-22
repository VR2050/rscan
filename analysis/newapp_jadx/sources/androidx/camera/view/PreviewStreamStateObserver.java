package androidx.camera.view;

import androidx.annotation.GuardedBy;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.arch.core.util.Function;
import androidx.camera.core.CameraInfo;
import androidx.camera.core.Logger;
import androidx.camera.core.impl.CameraCaptureCallback;
import androidx.camera.core.impl.CameraCaptureResult;
import androidx.camera.core.impl.CameraInfoInternal;
import androidx.camera.core.impl.CameraInternal;
import androidx.camera.core.impl.Observable;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.AsyncFunction;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.FutureChain;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.camera.view.PreviewStreamStateObserver;
import androidx.camera.view.PreviewView;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.lifecycle.MutableLiveData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public final class PreviewStreamStateObserver implements Observable.Observer<CameraInternal.State> {
    private static final String TAG = "StreamStateObserver";
    private final CameraInfoInternal mCameraInfoInternal;
    public InterfaceFutureC2413a<Void> mFlowFuture;
    private boolean mHasStartedPreviewStreamFlow = false;

    @GuardedBy("this")
    private PreviewView.StreamState mPreviewStreamState;
    private final MutableLiveData<PreviewView.StreamState> mPreviewStreamStateLiveData;
    private final PreviewViewImplementation mPreviewViewImplementation;

    public PreviewStreamStateObserver(CameraInfoInternal cameraInfoInternal, MutableLiveData<PreviewView.StreamState> mutableLiveData, PreviewViewImplementation previewViewImplementation) {
        this.mCameraInfoInternal = cameraInfoInternal;
        this.mPreviewStreamStateLiveData = mutableLiveData;
        this.mPreviewViewImplementation = previewViewImplementation;
        synchronized (this) {
            this.mPreviewStreamState = mutableLiveData.getValue();
        }
    }

    private void cancelFlow() {
        InterfaceFutureC2413a<Void> interfaceFutureC2413a = this.mFlowFuture;
        if (interfaceFutureC2413a != null) {
            interfaceFutureC2413a.cancel(false);
            this.mFlowFuture = null;
        }
    }

    @MainThread
    private void startPreviewStreamStateFlow(final CameraInfo cameraInfo) {
        updatePreviewStreamState(PreviewView.StreamState.IDLE);
        final ArrayList arrayList = new ArrayList();
        FutureChain transform = FutureChain.from(waitForCaptureResult(cameraInfo, arrayList)).transformAsync(new AsyncFunction() { // from class: e.a.c.g
            @Override // androidx.camera.core.impl.utils.futures.AsyncFunction
            public final InterfaceFutureC2413a apply(Object obj) {
                return PreviewStreamStateObserver.this.m146a((Void) obj);
            }
        }, CameraXExecutors.directExecutor()).transform(new Function() { // from class: e.a.c.e
            @Override // androidx.arch.core.util.Function
            public final Object apply(Object obj) {
                PreviewStreamStateObserver previewStreamStateObserver = PreviewStreamStateObserver.this;
                Objects.requireNonNull(previewStreamStateObserver);
                previewStreamStateObserver.updatePreviewStreamState(PreviewView.StreamState.STREAMING);
                return null;
            }
        }, CameraXExecutors.directExecutor());
        this.mFlowFuture = transform;
        Futures.addCallback(transform, new FutureCallback<Void>() { // from class: androidx.camera.view.PreviewStreamStateObserver.1
            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onFailure(Throwable th) {
                PreviewStreamStateObserver.this.mFlowFuture = null;
                if (arrayList.isEmpty()) {
                    return;
                }
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    ((CameraInfoInternal) cameraInfo).removeSessionCaptureCallback((CameraCaptureCallback) it.next());
                }
                arrayList.clear();
            }

            @Override // androidx.camera.core.impl.utils.futures.FutureCallback
            public void onSuccess(@Nullable Void r2) {
                PreviewStreamStateObserver.this.mFlowFuture = null;
            }
        }, CameraXExecutors.directExecutor());
    }

    private InterfaceFutureC2413a<Void> waitForCaptureResult(final CameraInfo cameraInfo, final List<CameraCaptureCallback> list) {
        return CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.c.f
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(final CallbackToFutureAdapter.Completer completer) {
                final PreviewStreamStateObserver previewStreamStateObserver = PreviewStreamStateObserver.this;
                final CameraInfo cameraInfo2 = cameraInfo;
                List list2 = list;
                Objects.requireNonNull(previewStreamStateObserver);
                CameraCaptureCallback cameraCaptureCallback = new CameraCaptureCallback() { // from class: androidx.camera.view.PreviewStreamStateObserver.2
                    @Override // androidx.camera.core.impl.CameraCaptureCallback
                    public void onCaptureCompleted(@NonNull CameraCaptureResult cameraCaptureResult) {
                        completer.set(null);
                        ((CameraInfoInternal) cameraInfo2).removeSessionCaptureCallback(this);
                    }
                };
                list2.add(cameraCaptureCallback);
                ((CameraInfoInternal) cameraInfo2).addSessionCaptureCallback(CameraXExecutors.directExecutor(), cameraCaptureCallback);
                return "waitForCaptureResult";
            }
        });
    }

    /* renamed from: a */
    public /* synthetic */ InterfaceFutureC2413a m146a(Void r1) {
        return this.mPreviewViewImplementation.waitForNextFrame();
    }

    public void clear() {
        cancelFlow();
    }

    @Override // androidx.camera.core.impl.Observable.Observer
    @MainThread
    public void onError(@NonNull Throwable th) {
        clear();
        updatePreviewStreamState(PreviewView.StreamState.IDLE);
    }

    public void updatePreviewStreamState(PreviewView.StreamState streamState) {
        synchronized (this) {
            if (this.mPreviewStreamState.equals(streamState)) {
                return;
            }
            this.mPreviewStreamState = streamState;
            Logger.m123d(TAG, "Update Preview stream state to " + streamState);
            this.mPreviewStreamStateLiveData.postValue(streamState);
        }
    }

    @Override // androidx.camera.core.impl.Observable.Observer
    @MainThread
    public void onNewData(@Nullable CameraInternal.State state) {
        if (state == CameraInternal.State.CLOSING || state == CameraInternal.State.CLOSED || state == CameraInternal.State.RELEASING || state == CameraInternal.State.RELEASED) {
            updatePreviewStreamState(PreviewView.StreamState.IDLE);
            if (this.mHasStartedPreviewStreamFlow) {
                this.mHasStartedPreviewStreamFlow = false;
                cancelFlow();
                return;
            }
            return;
        }
        if ((state == CameraInternal.State.OPENING || state == CameraInternal.State.OPEN || state == CameraInternal.State.PENDING_OPEN) && !this.mHasStartedPreviewStreamFlow) {
            startPreviewStreamStateFlow(this.mCameraInfoInternal);
            this.mHasStartedPreviewStreamFlow = true;
        }
    }
}
