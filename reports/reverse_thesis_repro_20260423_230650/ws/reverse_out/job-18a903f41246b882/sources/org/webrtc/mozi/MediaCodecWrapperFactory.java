package org.webrtc.mozi;

import java.io.IOException;

/* JADX INFO: loaded from: classes3.dex */
public interface MediaCodecWrapperFactory {
    MediaCodecWrapper createByCodecName(String str, int i, int i2) throws IOException;
}
