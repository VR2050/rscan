package org.webrtc.mozi.video.codecfactory;

import android.media.MediaCodec;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.MediaCodecWrapper;
import org.webrtc.mozi.MediaCodecWrapperFactoryImpl;

/* JADX INFO: loaded from: classes3.dex */
public class RTCReclaimMediaCodecWrapperFactory extends MediaCodecWrapperFactoryImpl {
    private static final String TAG = "ReclaimMediaCodecWrapperFactory";
    private int mLargeVideoHeight;
    private int mLargeVideoWidth;
    private List<MediaCodecWrapper> mSmallVideoCodecs = new LinkedList();

    public RTCReclaimMediaCodecWrapperFactory(int largeVideoWidth, int largeVideoHeight) {
        this.mLargeVideoWidth = largeVideoWidth;
        this.mLargeVideoHeight = largeVideoHeight;
    }

    private boolean isLargeVideo(int width, int height) {
        return width * height >= this.mLargeVideoWidth * this.mLargeVideoHeight;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void releaseMediaCodec(MediaCodecWrapper codecWrapper) {
        Logging.d(TAG, "Release media codec " + codecWrapper.hashCode());
        synchronized (this.mSmallVideoCodecs) {
            this.mSmallVideoCodecs.remove(codecWrapper);
        }
    }

    private MediaCodecWrapper didCreateCodec(String name, int width, int height) throws IOException {
        final MediaCodecWrapper codec = super.createByCodecName(name, width, height);
        if (codec != null) {
            codec.setReleaseListener(new Runnable() { // from class: org.webrtc.mozi.video.codecfactory.RTCReclaimMediaCodecWrapperFactory.1
                @Override // java.lang.Runnable
                public void run() {
                    RTCReclaimMediaCodecWrapperFactory.this.releaseMediaCodec(codec);
                }
            });
            if (!isLargeVideo(width, height)) {
                synchronized (this.mSmallVideoCodecs) {
                    this.mSmallVideoCodecs.add(codec);
                }
            }
        }
        return codec;
    }

    @Override // org.webrtc.mozi.MediaCodecWrapperFactoryImpl, org.webrtc.mozi.MediaCodecWrapperFactory
    public MediaCodecWrapper createByCodecName(String name, int width, int height) throws IOException {
        try {
            MediaCodecWrapper codec = didCreateCodec(name, width, height);
            Logging.d(TAG, "Create media codec success " + codec.hashCode() + "@" + width + "x" + height);
            return codec;
        } catch (MediaCodec.CodecException e) {
            if (!isLargeVideo(width, height)) {
                Logging.d(TAG, "Create media codec failed, not large video " + width + "x" + height);
                throw e;
            }
            if (e.getErrorCode() != 1100) {
                Logging.d(TAG, "Create media codec failed, not reach to limit error");
                throw e;
            }
            e.printStackTrace();
            Logging.d(TAG, "Media codec has reach to limit");
            MediaCodecWrapper codecToReclaim = null;
            synchronized (this.mSmallVideoCodecs) {
                for (MediaCodecWrapper codecWrapper : this.mSmallVideoCodecs) {
                    if (!codecWrapper.isReclaiming()) {
                        codecToReclaim = codecWrapper;
                    }
                }
                if (codecToReclaim == null) {
                    Logging.d(TAG, "No media codec to reclaim");
                    throw e;
                }
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                final MediaCodecWrapper finalCodecToReclaim = codecToReclaim;
                codecToReclaim.setReleaseListener(new Runnable() { // from class: org.webrtc.mozi.video.codecfactory.RTCReclaimMediaCodecWrapperFactory.2
                    @Override // java.lang.Runnable
                    public void run() {
                        RTCReclaimMediaCodecWrapperFactory.this.releaseMediaCodec(finalCodecToReclaim);
                        countDownLatch.countDown();
                    }
                });
                Logging.d(TAG, "Reclaim media codec start " + codecToReclaim.hashCode());
                codecToReclaim.reclaim();
                try {
                    if (countDownLatch.await(1000L, TimeUnit.MILLISECONDS)) {
                        Logging.d(TAG, "Reclaim media codec success " + codecToReclaim.hashCode());
                    } else {
                        Logging.d(TAG, "Reclaim media codec timeout, try force reclaim " + codecToReclaim.hashCode());
                        codecToReclaim.release();
                    }
                    MediaCodecWrapper codec2 = didCreateCodec(name, width, height);
                    Logging.d(TAG, "Create media codec success after reclaim " + codec2.hashCode() + "@" + width + "x" + height);
                    return codec2;
                } catch (InterruptedException interruptedException) {
                    interruptedException.printStackTrace();
                    Logging.d(TAG, "Reclaim media codec failed for interrupted exception");
                    throw e;
                }
            }
        }
    }
}
