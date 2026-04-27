package org.webrtc.mozi;

import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public interface VideoDecoderFactory {
    @Nullable
    @Deprecated
    VideoDecoder createDecoder(String str);

    @Nullable
    VideoDecoder createDecoder(VideoCodecInfo videoCodecInfo);

    VideoCodecInfo[] getSupportedCodecs();

    void setDynamicDecodePixelsThreshold(int i);
}
