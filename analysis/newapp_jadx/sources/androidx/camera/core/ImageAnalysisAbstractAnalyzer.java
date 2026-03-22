package androidx.camera.core;

import androidx.annotation.GuardedBy;
import androidx.annotation.Nullable;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageAnalysisAbstractAnalyzer;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.impl.ImageReaderProxy;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import androidx.core.os.OperationCanceledException;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public abstract class ImageAnalysisAbstractAnalyzer implements ImageReaderProxy.OnImageAvailableListener {
    private final Object mAnalyzerLock = new Object();
    private AtomicBoolean mIsClosed = new AtomicBoolean(false);
    private volatile int mRelativeRotation;

    @GuardedBy("mAnalyzerLock")
    private ImageAnalysis.Analyzer mSubscribedAnalyzer;

    @GuardedBy("mAnalyzerLock")
    private Executor mUserExecutor;

    /* renamed from: a */
    public /* synthetic */ void m117a(ImageProxy imageProxy, ImageAnalysis.Analyzer analyzer, CallbackToFutureAdapter.Completer completer) {
        if (isClosed()) {
            completer.setException(new OperationCanceledException("Closed before analysis"));
        } else {
            analyzer.analyze(new SettableImageProxy(imageProxy, ImmutableImageInfo.create(imageProxy.getImageInfo().getTagBundle(), imageProxy.getImageInfo().getTimestamp(), this.mRelativeRotation)));
            completer.set(null);
        }
    }

    public InterfaceFutureC2413a<Void> analyzeImage(final ImageProxy imageProxy) {
        final Executor executor;
        final ImageAnalysis.Analyzer analyzer;
        synchronized (this.mAnalyzerLock) {
            executor = this.mUserExecutor;
            analyzer = this.mSubscribedAnalyzer;
        }
        return (analyzer == null || executor == null) ? Futures.immediateFailedFuture(new OperationCanceledException("No analyzer or executor currently set.")) : CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.s
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(final CallbackToFutureAdapter.Completer completer) {
                final ImageAnalysisAbstractAnalyzer imageAnalysisAbstractAnalyzer = ImageAnalysisAbstractAnalyzer.this;
                Executor executor2 = executor;
                final ImageProxy imageProxy2 = imageProxy;
                final ImageAnalysis.Analyzer analyzer2 = analyzer;
                Objects.requireNonNull(imageAnalysisAbstractAnalyzer);
                executor2.execute(new Runnable() { // from class: e.a.a.r
                    @Override // java.lang.Runnable
                    public final void run() {
                        ImageAnalysisAbstractAnalyzer.this.m117a(imageProxy2, analyzer2, completer);
                    }
                });
                return "analyzeImage";
            }
        });
    }

    public void close() {
        this.mIsClosed.set(true);
    }

    public boolean isClosed() {
        return this.mIsClosed.get();
    }

    public void open() {
        this.mIsClosed.set(false);
    }

    public void setAnalyzer(@Nullable Executor executor, @Nullable ImageAnalysis.Analyzer analyzer) {
        synchronized (this.mAnalyzerLock) {
            this.mSubscribedAnalyzer = analyzer;
            this.mUserExecutor = executor;
        }
    }

    public void setRelativeRotation(int i2) {
        this.mRelativeRotation = i2;
    }
}
