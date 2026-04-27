package org.webrtc.mozi.audio;

import java.nio.ByteBuffer;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public class ExternalAudioSource {
    private static final int BUFFERS_PER_SECOND = 100;
    private static final int CALLBACK_BUFFER_SIZE_MS = 10;
    private static final String TAG = "ExternalAudioSource";
    private ByteBuffer byteBuffer;
    private final int bytesPerSample;
    private final int channels;
    private byte[] emptyBytes;
    private final long nativeAudopSource;
    private final int sampleRate;

    private static native void nativeCacheDirectBufferAddress(ByteBuffer byteBuffer, long j);

    private static native void nativeDataIsRecorded(int i, long j);

    public ExternalAudioSource(long nativeAudopSource, int bytesPerSample, int sampleRate, int channels) {
        this.nativeAudopSource = nativeAudopSource;
        this.bytesPerSample = bytesPerSample;
        this.sampleRate = sampleRate;
        this.channels = channels;
        init();
    }

    private void init() {
        int bytesPerFrame = this.channels * this.bytesPerSample;
        int framesPerBuffer = this.sampleRate / 100;
        this.byteBuffer = ByteBuffer.allocateDirect(bytesPerFrame * framesPerBuffer);
        Logging.d(TAG, "byteBuffer.capacity: " + this.byteBuffer.capacity());
        this.emptyBytes = new byte[this.byteBuffer.capacity()];
        nativeCacheDirectBufferAddress(this.byteBuffer, this.nativeAudopSource);
    }

    public void onDataIsRecorded(int size) {
        nativeDataIsRecorded(size, this.nativeAudopSource);
    }

    public int getBufferSize() {
        return this.byteBuffer.capacity();
    }

    public ByteBuffer getByteBuffer() {
        return this.byteBuffer;
    }

    public long getNativeAudopSource() {
        return this.nativeAudopSource;
    }
}
