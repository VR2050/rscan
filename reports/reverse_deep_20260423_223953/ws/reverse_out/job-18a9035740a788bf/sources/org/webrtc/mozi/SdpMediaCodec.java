package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SdpMediaCodec {
    private Integer frequency;
    private Boolean isVideo;
    private String name;
    private String profile;

    public SdpMediaCodec(String name, Boolean isVideo, Integer frequency, String profile) {
        this.name = name;
        this.isVideo = isVideo;
        this.frequency = frequency;
        this.profile = profile;
    }

    public String getName() {
        return this.name;
    }

    public Boolean getIsVideo() {
        return this.isVideo;
    }

    public Integer getFrequency() {
        return this.frequency;
    }

    public String getProfile() {
        return this.profile;
    }

    static SdpMediaCodec create(String name, Boolean isVideo, Integer frequency, String profile) {
        return new SdpMediaCodec(name, isVideo, frequency, profile);
    }
}
