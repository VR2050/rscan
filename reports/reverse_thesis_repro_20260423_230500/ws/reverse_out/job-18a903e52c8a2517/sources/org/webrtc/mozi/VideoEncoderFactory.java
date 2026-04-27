package org.webrtc.mozi;

import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public interface VideoEncoderFactory {
    @Nullable
    VideoEncoder createEncoder(VideoCodecInfo videoCodecInfo);

    VideoCodecInfo[] getSupportedCodecs();
}
