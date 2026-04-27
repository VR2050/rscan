package org.webrtc.mozi;

import com.google.android.gms.common.Scopes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public class SoftwareVideoEncoderFactory implements VideoEncoderFactory {
    private final boolean supportCHP;

    public SoftwareVideoEncoderFactory() {
        this.supportCHP = false;
    }

    public SoftwareVideoEncoderFactory(boolean supportCHP) {
        this.supportCHP = supportCHP;
    }

    @Override // org.webrtc.mozi.VideoEncoderFactory
    @Nullable
    public VideoEncoder createEncoder(VideoCodecInfo info) {
        if (info.name.equalsIgnoreCase("H264")) {
            return new H264Encoder();
        }
        if (info.name.equalsIgnoreCase("VP8")) {
            return new VP8Encoder();
        }
        if (info.name.equalsIgnoreCase("VP9") && VP9Encoder.nativeIsSupported()) {
            return new VP9Encoder();
        }
        if (info.name.equalsIgnoreCase("AV1") && AV1Encoder.nativeIsSupported()) {
            return new AV1Encoder();
        }
        return null;
    }

    @Override // org.webrtc.mozi.VideoEncoderFactory
    public VideoCodecInfo[] getSupportedCodecs() {
        return supportedCodecs(this.supportCHP);
    }

    static VideoCodecInfo[] supportedCodecs(boolean supportCHP) {
        List<VideoCodecInfo> codecs = new ArrayList<>();
        HashMap<String, String> baselineParams = new HashMap<>();
        baselineParams.put("profile-level-id", "42e01f");
        baselineParams.put("level-asymmetry-allowed", "1");
        baselineParams.put("packetization-mode", "1");
        codecs.add(new VideoCodecInfo("H264", baselineParams));
        if (supportCHP) {
            HashMap<String, String> highProfileParams = new HashMap<>();
            highProfileParams.put("profile-level-id", "640c1f");
            highProfileParams.put("level-asymmetry-allowed", "1");
            highProfileParams.put("packetization-mode", "1");
            codecs.add(new VideoCodecInfo("H264", highProfileParams));
        }
        codecs.add(new VideoCodecInfo("VP8", new HashMap()));
        if (VP9Encoder.nativeIsSupported()) {
            codecs.add(new VideoCodecInfo("VP9", new HashMap()));
        }
        if (AV1Encoder.nativeIsSupported()) {
            HashMap<String, String> av1ProfileParams = new HashMap<>();
            av1ProfileParams.put("level-idx", "8");
            av1ProfileParams.put(Scopes.PROFILE, "0");
            codecs.add(new VideoCodecInfo("AV1", av1ProfileParams));
        }
        return (VideoCodecInfo[]) codecs.toArray(new VideoCodecInfo[codecs.size()]);
    }
}
