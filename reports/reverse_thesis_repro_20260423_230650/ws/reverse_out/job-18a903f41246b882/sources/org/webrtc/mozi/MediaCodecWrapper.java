package org.webrtc.mozi;

import android.media.MediaCodec;
import android.media.MediaCrypto;
import android.media.MediaFormat;
import android.os.Bundle;
import android.view.Surface;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes3.dex */
public interface MediaCodecWrapper {
    void configure(MediaFormat mediaFormat, Surface surface, MediaCrypto mediaCrypto, int i);

    Surface createInputSurface();

    int dequeueInputBuffer(long j);

    int dequeueOutputBuffer(MediaCodec.BufferInfo bufferInfo, long j);

    void flush();

    ByteBuffer getInputBuffer(int i);

    ByteBuffer[] getInputBuffers();

    ByteBuffer getOutputBuffer(int i);

    ByteBuffer[] getOutputBuffers();

    MediaFormat getOutputFormat();

    boolean isReclaiming();

    boolean isReleased();

    void queueInputBuffer(int i, int i2, int i3, long j, int i4);

    void reclaim();

    void release();

    void releaseOutputBuffer(int i, boolean z);

    void setParameters(Bundle bundle);

    void setReleaseListener(Runnable runnable);

    void start();

    void stop();
}
