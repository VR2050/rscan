package org.webrtc.mozi;

import com.google.android.gms.common.Scopes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public class SoftwareVideoDecoderFactory implements VideoDecoderFactory {
    private static final String TAG = "SoftwareVideoDecoderFactory";
    private final boolean supportCHP;

    public SoftwareVideoDecoderFactory() {
        this.supportCHP = false;
    }

    public SoftwareVideoDecoderFactory(boolean supportCHP) {
        this.supportCHP = supportCHP;
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    @Nullable
    @Deprecated
    public VideoDecoder createDecoder(String codecType) {
        return createDecoder(new VideoCodecInfo(codecType, new HashMap()));
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    @Nullable
    public VideoDecoder createDecoder(VideoCodecInfo codecType) {
        if (codecType.getName().equalsIgnoreCase("H264")) {
            return new H264Decoder();
        }
        if (codecType.getName().equalsIgnoreCase("VP8")) {
            return new VP8Decoder();
        }
        if (codecType.getName().equalsIgnoreCase("VP9") && VP9Decoder.nativeIsSupported()) {
            return new VP9Decoder();
        }
        if (codecType.getName().equalsIgnoreCase("AV1") && AV1Decoder.nativeIsSupported()) {
            return new AV1Decoder();
        }
        return null;
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
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
        if (VP9Decoder.nativeIsSupported()) {
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

    @Override // org.webrtc.mozi.VideoDecoderFactory
    public void setDynamicDecodePixelsThreshold(int pixelsThreshold) {
    }
}
