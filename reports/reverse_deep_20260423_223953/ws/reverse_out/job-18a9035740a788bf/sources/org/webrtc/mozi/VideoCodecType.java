package org.webrtc.mozi;

import com.google.android.exoplayer2.util.MimeTypes;

/* JADX INFO: loaded from: classes3.dex */
enum VideoCodecType {
    VP8(MimeTypes.VIDEO_VP8),
    VP9(MimeTypes.VIDEO_VP9),
    H264("video/avc"),
    H265(MimeTypes.VIDEO_H265),
    AV1("video/av1");

    private final String mimeType;

    VideoCodecType(String mimeType) {
        this.mimeType = mimeType;
    }

    String mimeType() {
        return this.mimeType;
    }
}
