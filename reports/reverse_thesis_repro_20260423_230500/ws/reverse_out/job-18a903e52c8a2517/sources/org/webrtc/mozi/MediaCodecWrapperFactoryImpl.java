package org.webrtc.mozi;

import android.media.MediaCodec;
import android.media.MediaCrypto;
import android.media.MediaFormat;
import android.os.Bundle;
import android.view.Surface;
import java.io.IOException;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes3.dex */
public class MediaCodecWrapperFactoryImpl implements MediaCodecWrapperFactory {

    private static class MediaCodecWrapperImpl implements MediaCodecWrapper {
        private final MediaCodec mediaCodec;
        private volatile boolean reclaiming;
        private volatile Runnable releaseListener;
        private volatile boolean released;

        public MediaCodecWrapperImpl(MediaCodec mediaCodec) {
            this.mediaCodec = mediaCodec;
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void configure(MediaFormat format, Surface surface, MediaCrypto crypto, int flags) {
            this.mediaCodec.configure(format, surface, crypto, flags);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void start() {
            this.mediaCodec.start();
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void flush() {
            this.mediaCodec.flush();
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void stop() {
            this.mediaCodec.stop();
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void release() {
            this.mediaCodec.release();
            this.released = true;
            if (this.releaseListener != null) {
                this.releaseListener.run();
            }
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public int dequeueInputBuffer(long timeoutUs) {
            return this.mediaCodec.dequeueInputBuffer(timeoutUs);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void queueInputBuffer(int index, int offset, int size, long presentationTimeUs, int flags) {
            this.mediaCodec.queueInputBuffer(index, offset, size, presentationTimeUs, flags);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public int dequeueOutputBuffer(MediaCodec.BufferInfo info, long timeoutUs) {
            return this.mediaCodec.dequeueOutputBuffer(info, timeoutUs);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void releaseOutputBuffer(int index, boolean render) {
            this.mediaCodec.releaseOutputBuffer(index, render);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public MediaFormat getOutputFormat() {
            return this.mediaCodec.getOutputFormat();
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public ByteBuffer[] getInputBuffers() {
            return this.mediaCodec.getInputBuffers();
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public ByteBuffer[] getOutputBuffers() {
            return this.mediaCodec.getOutputBuffers();
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public ByteBuffer getInputBuffer(int index) {
            return this.mediaCodec.getInputBuffer(index);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public ByteBuffer getOutputBuffer(int index) {
            return this.mediaCodec.getOutputBuffer(index);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public Surface createInputSurface() {
            return this.mediaCodec.createInputSurface();
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void setParameters(Bundle params) {
            this.mediaCodec.setParameters(params);
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void reclaim() {
            this.reclaiming = true;
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public boolean isReclaiming() {
            return this.reclaiming;
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public boolean isReleased() {
            return this.released;
        }

        @Override // org.webrtc.mozi.MediaCodecWrapper
        public void setReleaseListener(Runnable releaseListener) {
            this.releaseListener = releaseListener;
        }
    }

    @Override // org.webrtc.mozi.MediaCodecWrapperFactory
    public MediaCodecWrapper createByCodecName(String name, int width, int height) throws IOException {
        return new MediaCodecWrapperImpl(MediaCodec.createByCodecName(name));
    }
}
