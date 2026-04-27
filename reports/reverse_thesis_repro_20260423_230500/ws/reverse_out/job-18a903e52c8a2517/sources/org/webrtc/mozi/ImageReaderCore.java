package org.webrtc.mozi;

import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.SystemClock;
import android.view.Surface;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/* JADX INFO: loaded from: classes3.dex */
public class ImageReaderCore {
    private static final boolean DEBUG = false;
    private static final int MAX_IMAGE_NUMBER = 20;
    private static final String TAG = "ImageReaderEncodeCore";
    private Handler mHandler;
    private ImageReader mImageReader;
    private Surface mInputSurface;
    private OnImageReaderCoreListener mOnImageReaderCoreListener;
    private boolean released = false;
    long pts = 0;
    private final int mColor = 1;
    private Lock lock = new ReentrantLock();
    private List<byte[]> mReusableBuffers = Collections.synchronizedList(new ArrayList());
    private List<ImageInfo> mList = Collections.synchronizedList(new ArrayList());

    public interface OnImageReaderCoreListener {
        void onImageArrive();

        void onRawData(byte[] bArr, int i, int i2, int i3);
    }

    private static class ImageInfo {
        final int color;
        final byte[] data;
        final int height;
        final int width;

        ImageInfo(byte[] data, int width, int height, int color) {
            this.data = data;
            this.width = width;
            this.height = height;
            this.color = color;
        }
    }

    public ImageReaderCore(int width, int height, OnImageReaderCoreListener listener, Handler handler) {
        this.mOnImageReaderCoreListener = null;
        this.mHandler = handler;
        this.mOnImageReaderCoreListener = listener;
        this.mImageReader = ImageReader.newInstance(width, height, 1, 20);
        this.mInputSurface = this.mImageReader.getSurface();
        this.mImageReader.setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() { // from class: org.webrtc.mozi.ImageReaderCore.1
            @Override // android.media.ImageReader.OnImageAvailableListener
            public void onImageAvailable(ImageReader reader) {
                Image image;
                ImageReaderCore.this.lock.lock();
                if (!ImageReaderCore.this.released) {
                    try {
                        image = reader.acquireNextImage();
                    } catch (Exception e) {
                        e.printStackTrace();
                        image = null;
                    }
                    if (image == null) {
                        ImageReaderCore.this.lock.unlock();
                        return;
                    }
                    Image.Plane[] planes = image.getPlanes();
                    int width2 = image.getWidth();
                    int height2 = image.getHeight();
                    int pixelStride = planes[0].getPixelStride();
                    int rowStride = planes[0].getRowStride();
                    int i = rowStride - (pixelStride * width2);
                    byte[] bytes = ImageReaderCore.this.getBuffer(pixelStride * width2 * height2);
                    ByteBuffer buffer = planes[0].getBuffer();
                    for (int i2 = 0; i2 < height2; i2++) {
                        try {
                            try {
                                buffer.position(i2 * rowStride);
                                int offset = i2 * width2 * pixelStride;
                                buffer.get(bytes, offset, pixelStride * width2);
                            } catch (Throwable th) {
                                image.close();
                                buffer.clear();
                                throw th;
                            }
                        } catch (IllegalStateException ie) {
                            ie.printStackTrace();
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                    if (ImageReaderCore.this.mOnImageReaderCoreListener != null) {
                        ImageReaderCore.this.mOnImageReaderCoreListener.onRawData(bytes, width2, height2, 1);
                    }
                    ImageReaderCore.this.mReusableBuffers.add(bytes);
                    image.close();
                    buffer.clear();
                    if (ImageReaderCore.this.mOnImageReaderCoreListener != null) {
                        ImageReaderCore.this.mOnImageReaderCoreListener.onImageArrive();
                    }
                }
                ImageReaderCore.this.lock.unlock();
            }
        }, this.mHandler);
    }

    public void setImageReaderCoreListener(OnImageReaderCoreListener onImageReaderCoreListener) {
        this.mOnImageReaderCoreListener = onImageReaderCoreListener;
    }

    public Surface getInputSurface() {
        return this.mInputSurface;
    }

    public synchronized void updatePTS(long pts) {
        this.pts = pts;
    }

    private class EncoderThread extends Thread {
        private EncoderThread() {
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            while (ImageReaderCore.this.mImageReader != null) {
                if (!ImageReaderCore.this.mList.isEmpty()) {
                    ImageInfo info = (ImageInfo) ImageReaderCore.this.mList.remove(0);
                    byte[] data = info.data;
                    if (ImageReaderCore.this.mOnImageReaderCoreListener != null) {
                        ImageReaderCore.this.mOnImageReaderCoreListener.onRawData(data, info.width, info.height, info.color);
                    }
                    ImageReaderCore.this.mReusableBuffers.add(data);
                } else {
                    SystemClock.sleep(10L);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public byte[] getBuffer(int length) {
        if (this.mReusableBuffers.isEmpty()) {
            return new byte[length];
        }
        return this.mReusableBuffers.remove(0);
    }

    public void release() {
        try {
            this.lock.lock();
            this.released = true;
            if (this.mImageReader != null) {
                this.mImageReader.setOnImageAvailableListener(null, this.mHandler);
                this.mImageReader.close();
                this.mImageReader = null;
            }
            this.lock.unlock();
            this.mList.clear();
            this.mReusableBuffers.clear();
            this.mHandler = null;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
