package org.webrtc.mozi;

import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class VideoMediaCodecConfig {
    private final List<HardwareModel> decoders;
    private final List<HardwareModel> encoders;

    public VideoMediaCodecConfig(List<HardwareModel> encoders, List<HardwareModel> decoders) {
        this.encoders = encoders;
        this.decoders = decoders;
    }

    public List<HardwareModel> getHardwareEncoderSupportList() {
        return this.encoders;
    }

    public List<HardwareModel> getHardwareDecoderSupportList() {
        return this.decoders;
    }

    static VideoMediaCodecConfig create(List<HardwareModel> encoders, List<HardwareModel> decoders) {
        return new VideoMediaCodecConfig(encoders, decoders);
    }
}
