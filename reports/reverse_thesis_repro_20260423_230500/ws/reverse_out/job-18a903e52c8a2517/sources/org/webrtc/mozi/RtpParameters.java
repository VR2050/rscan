package org.webrtc.mozi;

import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.webrtc.mozi.MediaStreamTrack;

/* JADX INFO: loaded from: classes3.dex */
public class RtpParameters {
    public final List<Codec> codecs;
    public DegradationPreference degradationPreference = DegradationPreference.MAINTAIN_RESOLUTION;
    public final List<Encoding> encodings;
    public final ExtraConfig extraConfig;
    private final List<HeaderExtension> headerExtensions;
    private final Rtcp rtcp;
    public final String transactionId;

    public enum DegradationPreference {
        DISABLED,
        MAINTAIN_FRAMERATE,
        MAINTAIN_RESOLUTION,
        BALANCED
    }

    public static class Encoding {
        public boolean active;

        @Nullable
        public Integer maxBitrateBps;

        @Nullable
        public Integer minBitrateBps;
        public Long ssrc;

        Encoding(boolean active, Integer maxBitrateBps, Integer minBitrateBps, Long ssrc) {
            this.active = true;
            this.active = active;
            this.maxBitrateBps = maxBitrateBps;
            this.minBitrateBps = minBitrateBps;
            this.ssrc = ssrc;
        }

        boolean getActive() {
            return this.active;
        }

        @Nullable
        Integer getMaxBitrateBps() {
            return this.maxBitrateBps;
        }

        @Nullable
        Integer getMinBitrateBps() {
            return this.minBitrateBps;
        }

        Long getSsrc() {
            return this.ssrc;
        }
    }

    public static class Codec {
        public Integer clockRate;
        MediaStreamTrack.MediaType kind;
        public String name;
        public Integer numChannels;
        public Map<String, String> parameters;
        public int payloadType;

        Codec(int payloadType, String name, MediaStreamTrack.MediaType kind, Integer clockRate, Integer numChannels, Map<String, String> parameters) {
            this.payloadType = payloadType;
            this.name = name;
            this.kind = kind;
            this.clockRate = clockRate;
            this.numChannels = numChannels;
            this.parameters = parameters;
        }

        int getPayloadType() {
            return this.payloadType;
        }

        String getName() {
            return this.name;
        }

        MediaStreamTrack.MediaType getKind() {
            return this.kind;
        }

        Integer getClockRate() {
            return this.clockRate;
        }

        Integer getNumChannels() {
            return this.numChannels;
        }

        Map getParameters() {
            return this.parameters;
        }
    }

    public static class Rtcp {
        private final String cname;
        private final boolean reducedSize;

        Rtcp(String cname, boolean reducedSize) {
            this.cname = cname;
            this.reducedSize = reducedSize;
        }

        public String getCname() {
            return this.cname;
        }

        public boolean getReducedSize() {
            return this.reducedSize;
        }
    }

    public static class HeaderExtension {
        private final boolean encrypted;
        private final int id;
        private final String uri;

        HeaderExtension(String uri, int id, boolean encrypted) {
            this.uri = uri;
            this.id = id;
            this.encrypted = encrypted;
        }

        public String getUri() {
            return this.uri;
        }

        public int getId() {
            return this.id;
        }

        public boolean getEncrypted() {
            return this.encrypted;
        }
    }

    public static class ExtraConfig {
        public boolean forcedFallbackSoftware;

        ExtraConfig(boolean forcedFallbackSoftware) {
            this.forcedFallbackSoftware = forcedFallbackSoftware;
        }

        public boolean getForcedFallbackSoftware() {
            return this.forcedFallbackSoftware;
        }
    }

    RtpParameters(String transactionId, Rtcp rtcp, List<HeaderExtension> headerExtensions, List<Encoding> encodings, List<Codec> codecs, ExtraConfig extraConfig) {
        this.transactionId = transactionId;
        this.rtcp = rtcp;
        this.headerExtensions = headerExtensions;
        this.encodings = encodings;
        this.codecs = codecs;
        this.extraConfig = extraConfig;
    }

    String getTransactionId() {
        return this.transactionId;
    }

    public Rtcp getRtcp() {
        return this.rtcp;
    }

    public List<HeaderExtension> getHeaderExtensions() {
        return this.headerExtensions;
    }

    List<Encoding> getEncodings() {
        return this.encodings;
    }

    List<Codec> getCodecs() {
        return this.codecs;
    }

    ExtraConfig getExtraConfig() {
        return this.extraConfig;
    }

    DegradationPreference getDegradationPreference() {
        return this.degradationPreference;
    }
}
