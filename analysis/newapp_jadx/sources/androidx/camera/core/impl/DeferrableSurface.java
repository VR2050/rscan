package androidx.camera.core.impl;

import android.util.Log;
import android.view.Surface;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.camera.core.Logger;
import androidx.camera.core.impl.DeferrableSurface;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import java.util.concurrent.atomic.AtomicInteger;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public abstract class DeferrableSurface {

    @GuardedBy("mLock")
    private CallbackToFutureAdapter.Completer<Void> mTerminationCompleter;
    private final InterfaceFutureC2413a<Void> mTerminationFuture;
    private static final String TAG = "DeferrableSurface";
    private static final boolean DEBUG = Logger.isDebugEnabled(TAG);
    private static final AtomicInteger USED_COUNT = new AtomicInteger(0);
    private static final AtomicInteger TOTAL_COUNT = new AtomicInteger(0);
    private final Object mLock = new Object();

    @GuardedBy("mLock")
    private int mUseCount = 0;

    @GuardedBy("mLock")
    private boolean mClosed = false;

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public static final class SurfaceClosedException extends Exception {
        public DeferrableSurface mDeferrableSurface;

        public SurfaceClosedException(@NonNull String str, @NonNull DeferrableSurface deferrableSurface) {
            super(str);
            this.mDeferrableSurface = deferrableSurface;
        }

        @NonNull
        public DeferrableSurface getDeferrableSurface() {
            return this.mDeferrableSurface;
        }
    }

    public static final class SurfaceUnavailableException extends Exception {
        public SurfaceUnavailableException(@NonNull String str) {
            super(str);
        }
    }

    public DeferrableSurface() {
        InterfaceFutureC2413a<Void> future = CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.u1.f
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(CallbackToFutureAdapter.Completer completer) {
                return DeferrableSurface.this.m139a(completer);
            }
        });
        this.mTerminationFuture = future;
        if (Logger.isDebugEnabled(TAG)) {
            printGlobalDebugCounts("Surface created", TOTAL_COUNT.incrementAndGet(), USED_COUNT.get());
            final String stackTraceString = Log.getStackTraceString(new Exception());
            future.addListener(new Runnable() { // from class: e.a.a.u1.e
                @Override // java.lang.Runnable
                public final void run() {
                    DeferrableSurface.this.m140b(stackTraceString);
                }
            }, CameraXExecutors.directExecutor());
        }
    }

    private void printGlobalDebugCounts(@NonNull String str, int i2, int i3) {
        if (!DEBUG && Logger.isDebugEnabled(TAG)) {
            Logger.m123d(TAG, "DeferrableSurface usage statistics may be inaccurate since debug logging was not enabled at static initialization time. App restart may be required to enable accurate usage statistics.");
        }
        Logger.m123d(TAG, str + "[total_surfaces=" + i2 + ", used_surfaces=" + i3 + "](" + this + "}");
    }

    /* renamed from: a */
    public /* synthetic */ Object m139a(CallbackToFutureAdapter.Completer completer) {
        synchronized (this.mLock) {
            this.mTerminationCompleter = completer;
        }
        return "DeferrableSurface-termination(" + this + ChineseToPinyinResource.Field.RIGHT_BRACKET;
    }

    /* renamed from: b */
    public /* synthetic */ void m140b(String str) {
        try {
            this.mTerminationFuture.get();
            printGlobalDebugCounts("Surface terminated", TOTAL_COUNT.decrementAndGet(), USED_COUNT.get());
        } catch (Exception e2) {
            Logger.m125e(TAG, "Unexpected surface termination for " + this + "\nStack Trace:\n" + str);
            synchronized (this.mLock) {
                throw new IllegalArgumentException(String.format("DeferrableSurface %s [closed: %b, use_count: %s] terminated with unexpected exception.", this, Boolean.valueOf(this.mClosed), Integer.valueOf(this.mUseCount)), e2);
            }
        }
    }

    public final void close() {
        CallbackToFutureAdapter.Completer<Void> completer;
        synchronized (this.mLock) {
            if (this.mClosed) {
                completer = null;
            } else {
                this.mClosed = true;
                if (this.mUseCount == 0) {
                    completer = this.mTerminationCompleter;
                    this.mTerminationCompleter = null;
                } else {
                    completer = null;
                }
                if (Logger.isDebugEnabled(TAG)) {
                    Logger.m123d(TAG, "surface closed,  useCount=" + this.mUseCount + " closed=true " + this);
                }
            }
        }
        if (completer != null) {
            completer.set(null);
        }
    }

    public void decrementUseCount() {
        CallbackToFutureAdapter.Completer<Void> completer;
        synchronized (this.mLock) {
            int i2 = this.mUseCount;
            if (i2 == 0) {
                throw new IllegalStateException("Decrementing use count occurs more times than incrementing");
            }
            int i3 = i2 - 1;
            this.mUseCount = i3;
            if (i3 == 0 && this.mClosed) {
                completer = this.mTerminationCompleter;
                this.mTerminationCompleter = null;
            } else {
                completer = null;
            }
            if (Logger.isDebugEnabled(TAG)) {
                Logger.m123d(TAG, "use count-1,  useCount=" + this.mUseCount + " closed=" + this.mClosed + " " + this);
                if (this.mUseCount == 0) {
                    printGlobalDebugCounts("Surface no longer in use", TOTAL_COUNT.get(), USED_COUNT.decrementAndGet());
                }
            }
        }
        if (completer != null) {
            completer.set(null);
        }
    }

    @NonNull
    public final InterfaceFutureC2413a<Surface> getSurface() {
        synchronized (this.mLock) {
            if (this.mClosed) {
                return Futures.immediateFailedFuture(new SurfaceClosedException("DeferrableSurface already closed.", this));
            }
            return provideSurface();
        }
    }

    @NonNull
    public InterfaceFutureC2413a<Void> getTerminationFuture() {
        return Futures.nonCancellationPropagating(this.mTerminationFuture);
    }

    @RestrictTo({RestrictTo.Scope.TESTS})
    public int getUseCount() {
        int i2;
        synchronized (this.mLock) {
            i2 = this.mUseCount;
        }
        return i2;
    }

    public void incrementUseCount() {
        synchronized (this.mLock) {
            int i2 = this.mUseCount;
            if (i2 == 0 && this.mClosed) {
                throw new SurfaceClosedException("Cannot begin use on a closed surface.", this);
            }
            this.mUseCount = i2 + 1;
            if (Logger.isDebugEnabled(TAG)) {
                if (this.mUseCount == 1) {
                    printGlobalDebugCounts("New surface in use", TOTAL_COUNT.get(), USED_COUNT.incrementAndGet());
                }
                Logger.m123d(TAG, "use count+1, useCount=" + this.mUseCount + " " + this);
            }
        }
    }

    @NonNull
    public abstract InterfaceFutureC2413a<Surface> provideSurface();
}
