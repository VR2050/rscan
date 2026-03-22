package androidx.camera.core.impl;

import android.os.SystemClock;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.impl.Observable;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.core.util.Preconditions;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public final class LiveDataObservable<T> implements Observable<T> {
    public final MutableLiveData<Result<T>> mLiveData = new MutableLiveData<>();

    @GuardedBy("mObservers")
    private final Map<Observable.Observer<T>, LiveDataObserverAdapter<T>> mObservers = new HashMap();

    public static final class LiveDataObserverAdapter<T> implements Observer<Result<T>> {
        public final AtomicBoolean mActive = new AtomicBoolean(true);
        public final Executor mExecutor;
        public final Observable.Observer<T> mObserver;

        public LiveDataObserverAdapter(@NonNull Executor executor, @NonNull Observable.Observer<T> observer) {
            this.mExecutor = executor;
            this.mObserver = observer;
        }

        public void disable() {
            this.mActive.set(false);
        }

        @Override // androidx.lifecycle.Observer
        public void onChanged(@NonNull final Result<T> result) {
            this.mExecutor.execute(new Runnable() { // from class: androidx.camera.core.impl.LiveDataObservable.LiveDataObserverAdapter.1
                /* JADX WARN: Multi-variable type inference failed */
                @Override // java.lang.Runnable
                public void run() {
                    if (LiveDataObserverAdapter.this.mActive.get()) {
                        if (result.completedSuccessfully()) {
                            LiveDataObserverAdapter.this.mObserver.onNewData(result.getValue());
                        } else {
                            Preconditions.checkNotNull(result.getError());
                            LiveDataObserverAdapter.this.mObserver.onError(result.getError());
                        }
                    }
                }
            });
        }
    }

    public static final class Result<T> {

        @Nullable
        private Throwable mError;

        @Nullable
        private T mValue;

        private Result(@Nullable T t, @Nullable Throwable th) {
            this.mValue = t;
            this.mError = th;
        }

        public static <T> Result<T> fromError(@NonNull Throwable th) {
            return new Result<>(null, (Throwable) Preconditions.checkNotNull(th));
        }

        public static <T> Result<T> fromValue(@Nullable T t) {
            return new Result<>(t, null);
        }

        public boolean completedSuccessfully() {
            return this.mError == null;
        }

        @Nullable
        public Throwable getError() {
            return this.mError;
        }

        @Nullable
        public T getValue() {
            if (completedSuccessfully()) {
                return this.mValue;
            }
            throw new IllegalStateException("Result contains an error. Does not contain a value.");
        }

        @NonNull
        public String toString() {
            String sb;
            StringBuilder m586H = C1499a.m586H("[Result: <");
            if (completedSuccessfully()) {
                StringBuilder m586H2 = C1499a.m586H("Value: ");
                m586H2.append(this.mValue);
                sb = m586H2.toString();
            } else {
                StringBuilder m586H3 = C1499a.m586H("Error: ");
                m586H3.append(this.mError);
                sb = m586H3.toString();
            }
            return C1499a.m582D(m586H, sb, ">]");
        }
    }

    @Override // androidx.camera.core.impl.Observable
    public void addObserver(@NonNull Executor executor, @NonNull Observable.Observer<T> observer) {
        synchronized (this.mObservers) {
            final LiveDataObserverAdapter<T> liveDataObserverAdapter = this.mObservers.get(observer);
            if (liveDataObserverAdapter != null) {
                liveDataObserverAdapter.disable();
            }
            final LiveDataObserverAdapter<T> liveDataObserverAdapter2 = new LiveDataObserverAdapter<>(executor, observer);
            this.mObservers.put(observer, liveDataObserverAdapter2);
            CameraXExecutors.mainThreadExecutor().execute(new Runnable() { // from class: androidx.camera.core.impl.LiveDataObservable.2
                @Override // java.lang.Runnable
                public void run() {
                    LiveDataObservable.this.mLiveData.removeObserver(liveDataObserverAdapter);
                    LiveDataObservable.this.mLiveData.observeForever(liveDataObserverAdapter2);
                }
            });
        }
    }

    @Override // androidx.camera.core.impl.Observable
    @NonNull
    public InterfaceFutureC2413a<T> fetchData() {
        return CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver<T>() { // from class: androidx.camera.core.impl.LiveDataObservable.1
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            @Nullable
            public Object attachCompleter(@NonNull final CallbackToFutureAdapter.Completer<T> completer) {
                CameraXExecutors.mainThreadExecutor().execute(new Runnable() { // from class: androidx.camera.core.impl.LiveDataObservable.1.1
                    @Override // java.lang.Runnable
                    public void run() {
                        Result<T> value = LiveDataObservable.this.mLiveData.getValue();
                        if (value == null) {
                            completer.setException(new IllegalStateException("Observable has not yet been initialized with a value."));
                        } else if (value.completedSuccessfully()) {
                            completer.set(value.getValue());
                        } else {
                            Preconditions.checkNotNull(value.getError());
                            completer.setException(value.getError());
                        }
                    }
                });
                return LiveDataObservable.this + " [fetch@" + SystemClock.uptimeMillis() + "]";
            }
        });
    }

    @NonNull
    public LiveData<Result<T>> getLiveData() {
        return this.mLiveData;
    }

    public void postError(@NonNull Throwable th) {
        this.mLiveData.postValue(Result.fromError(th));
    }

    public void postValue(@Nullable T t) {
        this.mLiveData.postValue(Result.fromValue(t));
    }

    @Override // androidx.camera.core.impl.Observable
    public void removeObserver(@NonNull Observable.Observer<T> observer) {
        synchronized (this.mObservers) {
            final LiveDataObserverAdapter<T> remove = this.mObservers.remove(observer);
            if (remove != null) {
                remove.disable();
                CameraXExecutors.mainThreadExecutor().execute(new Runnable() { // from class: androidx.camera.core.impl.LiveDataObservable.3
                    @Override // java.lang.Runnable
                    public void run() {
                        LiveDataObservable.this.mLiveData.removeObserver(remove);
                    }
                });
            }
        }
    }
}
