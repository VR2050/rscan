package androidx.camera.core;

import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.camera.core.ForwardingImageProxy;
import androidx.camera.core.ImageAnalysisNonBlockingAnalyzer;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.impl.ImageReaderProxy;
import androidx.camera.core.impl.utils.executor.CameraXExecutors;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.Futures;
import java.lang.ref.WeakReference;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class ImageAnalysisNonBlockingAnalyzer extends ImageAnalysisAbstractAnalyzer {
    private static final String TAG = "NonBlockingCallback";
    public final Executor mBackgroundExecutor;

    @GuardedBy("this")
    private ImageProxy mCachedImage;
    private final AtomicReference<CacheAnalyzingImageProxy> mPostedImage = new AtomicReference<>();
    private final AtomicLong mPostedImageTimestamp = new AtomicLong();

    public static class CacheAnalyzingImageProxy extends ForwardingImageProxy {
        private boolean mClosed;
        public WeakReference<ImageAnalysisNonBlockingAnalyzer> mNonBlockingAnalyzerWeakReference;

        public CacheAnalyzingImageProxy(ImageProxy imageProxy, ImageAnalysisNonBlockingAnalyzer imageAnalysisNonBlockingAnalyzer) {
            super(imageProxy);
            this.mClosed = false;
            this.mNonBlockingAnalyzerWeakReference = new WeakReference<>(imageAnalysisNonBlockingAnalyzer);
            addOnImageCloseListener(new ForwardingImageProxy.OnImageCloseListener() { // from class: e.a.a.t
                @Override // androidx.camera.core.ForwardingImageProxy.OnImageCloseListener
                public final void onImageClose(ImageProxy imageProxy2) {
                    ImageAnalysisNonBlockingAnalyzer.CacheAnalyzingImageProxy.this.m118b(imageProxy2);
                }
            });
        }

        /* renamed from: b */
        public /* synthetic */ void m118b(ImageProxy imageProxy) {
            this.mClosed = true;
            final ImageAnalysisNonBlockingAnalyzer imageAnalysisNonBlockingAnalyzer = this.mNonBlockingAnalyzerWeakReference.get();
            if (imageAnalysisNonBlockingAnalyzer != null) {
                imageAnalysisNonBlockingAnalyzer.mBackgroundExecutor.execute(new Runnable() { // from class: e.a.a.t1
                    @Override // java.lang.Runnable
                    public final void run() {
                        ImageAnalysisNonBlockingAnalyzer.this.analyzeCachedImage();
                    }
                });
            }
        }

        public boolean isClosed() {
            return this.mClosed;
        }
    }

    public ImageAnalysisNonBlockingAnalyzer(Executor executor) {
        this.mBackgroundExecutor = executor;
        open();
    }

    private synchronized void analyze(@NonNull ImageProxy imageProxy) {
        if (isClosed()) {
            imageProxy.close();
            return;
        }
        CacheAnalyzingImageProxy cacheAnalyzingImageProxy = this.mPostedImage.get();
        if (cacheAnalyzingImageProxy != null && imageProxy.getImageInfo().getTimestamp() <= this.mPostedImageTimestamp.get()) {
            imageProxy.close();
            return;
        }
        if (cacheAnalyzingImageProxy == null || cacheAnalyzingImageProxy.isClosed()) {
            final CacheAnalyzingImageProxy cacheAnalyzingImageProxy2 = new CacheAnalyzingImageProxy(imageProxy, this);
            this.mPostedImage.set(cacheAnalyzingImageProxy2);
            this.mPostedImageTimestamp.set(cacheAnalyzingImageProxy2.getImageInfo().getTimestamp());
            Futures.addCallback(analyzeImage(cacheAnalyzingImageProxy2), new FutureCallback<Void>() { // from class: androidx.camera.core.ImageAnalysisNonBlockingAnalyzer.1
                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onFailure(Throwable th) {
                    cacheAnalyzingImageProxy2.close();
                }

                @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                public void onSuccess(Void r1) {
                }
            }, CameraXExecutors.directExecutor());
            return;
        }
        ImageProxy imageProxy2 = this.mCachedImage;
        if (imageProxy2 != null) {
            imageProxy2.close();
        }
        this.mCachedImage = imageProxy;
    }

    public synchronized void analyzeCachedImage() {
        ImageProxy imageProxy = this.mCachedImage;
        if (imageProxy != null) {
            this.mCachedImage = null;
            analyze(imageProxy);
        }
    }

    @Override // androidx.camera.core.ImageAnalysisAbstractAnalyzer
    public synchronized void close() {
        super.close();
        ImageProxy imageProxy = this.mCachedImage;
        if (imageProxy != null) {
            imageProxy.close();
            this.mCachedImage = null;
        }
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy.OnImageAvailableListener
    public void onImageAvailable(@NonNull ImageReaderProxy imageReaderProxy) {
        ImageProxy acquireLatestImage = imageReaderProxy.acquireLatestImage();
        if (acquireLatestImage == null) {
            return;
        }
        analyze(acquireLatestImage);
    }

    @Override // androidx.camera.core.ImageAnalysisAbstractAnalyzer
    public synchronized void open() {
        super.open();
        ImageProxy imageProxy = this.mCachedImage;
        if (imageProxy != null) {
            imageProxy.close();
            this.mCachedImage = null;
        }
    }
}
