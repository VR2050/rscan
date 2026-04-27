package org.webrtc.mozi.owtbase;

import java.util.ArrayList;
import java.util.List;
import org.webrtc.mozi.RtpParameters;

/* JADX INFO: loaded from: classes3.dex */
public final class PublishOptions {
    final List<AudioEncodingParameters> audioEncodingParameters;
    final RtpParameters.DegradationPreference degradationPreference;
    final long timeoutMs;
    final List<VideoEncodingParameters> videoEncodingParameters;

    private PublishOptions(List<AudioEncodingParameters> audioParameters, List<VideoEncodingParameters> videoParameters, RtpParameters.DegradationPreference degradationPreference, long timeoutMs) {
        this.audioEncodingParameters = audioParameters;
        this.videoEncodingParameters = videoParameters;
        this.degradationPreference = degradationPreference;
        this.timeoutMs = timeoutMs;
    }

    public List<AudioEncodingParameters> getAudio() {
        return this.audioEncodingParameters;
    }

    public List<VideoEncodingParameters> getVideo() {
        return this.videoEncodingParameters;
    }

    public long getTimeoutMs() {
        return this.timeoutMs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        final List<AudioEncodingParameters> audioEncodingParameters = new ArrayList();
        final List<VideoEncodingParameters> videoEncodingParameters = new ArrayList();
        long timeouts = 120000;
        public RtpParameters.DegradationPreference degradationPreference = RtpParameters.DegradationPreference.MAINTAIN_RESOLUTION;

        Builder() {
        }

        public Builder addVideoParameter(VideoEncodingParameters parameter) {
            this.videoEncodingParameters.add(parameter);
            return this;
        }

        public Builder addAudioParameter(AudioEncodingParameters parameter) {
            this.audioEncodingParameters.add(parameter);
            return this;
        }

        public Builder setTimeouts(long timeouts) {
            this.timeouts = timeouts;
            return this;
        }

        public Builder setDegradationPreference(RtpParameters.DegradationPreference degradationPreference) {
            this.degradationPreference = degradationPreference;
            return this;
        }

        public PublishOptions build() {
            return new PublishOptions(this.audioEncodingParameters, this.videoEncodingParameters, this.degradationPreference, this.timeouts);
        }
    }
}
