package androidx.camera.core;

import android.media.Image;
import android.media.ImageReader;
import android.view.Surface;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.AndroidImageReaderProxy;
import androidx.camera.core.impl.ImageReaderProxy;
import androidx.camera.core.impl.utils.MainThreadAsyncHandler;
import java.util.Objects;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class AndroidImageReaderProxy implements ImageReaderProxy {

    @GuardedBy("this")
    private final ImageReader mImageReader;

    public AndroidImageReaderProxy(ImageReader imageReader) {
        this.mImageReader = imageReader;
    }

    private boolean isImageReaderContextNotInitializedException(RuntimeException runtimeException) {
        return "ImageReaderContext is not initialized".equals(runtimeException.getMessage());
    }

    private /* synthetic */ void lambda$setOnImageAvailableListener$0(ImageReaderProxy.OnImageAvailableListener onImageAvailableListener) {
        onImageAvailableListener.onImageAvailable(this);
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    @Nullable
    public synchronized ImageProxy acquireLatestImage() {
        Image image;
        try {
            image = this.mImageReader.acquireLatestImage();
        } catch (RuntimeException e2) {
            if (!isImageReaderContextNotInitializedException(e2)) {
                throw e2;
            }
            image = null;
        }
        if (image == null) {
            return null;
        }
        return new AndroidImageProxy(image);
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    @Nullable
    public synchronized ImageProxy acquireNextImage() {
        Image image;
        try {
            image = this.mImageReader.acquireNextImage();
        } catch (RuntimeException e2) {
            if (!isImageReaderContextNotInitializedException(e2)) {
                throw e2;
            }
            image = null;
        }
        if (image == null) {
            return null;
        }
        return new AndroidImageProxy(image);
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    public synchronized void clearOnImageAvailableListener() {
        this.mImageReader.setOnImageAvailableListener(null, null);
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    public synchronized void close() {
        this.mImageReader.close();
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    public synchronized int getHeight() {
        return this.mImageReader.getHeight();
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    public synchronized int getImageFormat() {
        return this.mImageReader.getImageFormat();
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    public synchronized int getMaxImages() {
        return this.mImageReader.getMaxImages();
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    @Nullable
    public synchronized Surface getSurface() {
        return this.mImageReader.getSurface();
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    public synchronized int getWidth() {
        return this.mImageReader.getWidth();
    }

    @Override // androidx.camera.core.impl.ImageReaderProxy
    public synchronized void setOnImageAvailableListener(@NonNull final ImageReaderProxy.OnImageAvailableListener onImageAvailableListener, @NonNull final Executor executor) {
        this.mImageReader.setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() { // from class: e.a.a.b
            @Override // android.media.ImageReader.OnImageAvailableListener
            public final void onImageAvailable(ImageReader imageReader) {
                final AndroidImageReaderProxy androidImageReaderProxy = AndroidImageReaderProxy.this;
                Executor executor2 = executor;
                final ImageReaderProxy.OnImageAvailableListener onImageAvailableListener2 = onImageAvailableListener;
                Objects.requireNonNull(androidImageReaderProxy);
                executor2.execute(new Runnable() { // from class: e.a.a.c
                    @Override // java.lang.Runnable
                    public final void run() {
                        AndroidImageReaderProxy androidImageReaderProxy2 = AndroidImageReaderProxy.this;
                        ImageReaderProxy.OnImageAvailableListener onImageAvailableListener3 = onImageAvailableListener2;
                        Objects.requireNonNull(androidImageReaderProxy2);
                        onImageAvailableListener3.onImageAvailable(androidImageReaderProxy2);
                    }
                });
            }
        }, MainThreadAsyncHandler.getInstance());
    }
}
