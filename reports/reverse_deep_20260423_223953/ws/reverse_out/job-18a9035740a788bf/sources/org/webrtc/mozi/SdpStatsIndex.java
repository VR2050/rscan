package org.webrtc.mozi;

import android.util.LongSparseArray;
import android.util.SparseArray;

/* JADX INFO: loaded from: classes3.dex */
public class SdpStatsIndex {
    private final Long audioFirstSsrc;
    private final Boolean effective;
    private final String iceUfrag;
    private final String sessionId;
    private final Long videoFirstSsrc;
    private final LongSparseArray<Integer> ssrcsWithMediaType = new LongSparseArray<>();
    private final SparseArray<SdpMediaCodec> mediaCodecs = new SparseArray<>();

    public SdpStatsIndex(Boolean effective, String sessionId, String iceUfrag, Long audioFirstSsrc, Long videoFirstSsrc) {
        this.effective = effective;
        this.sessionId = sessionId;
        this.iceUfrag = iceUfrag;
        this.audioFirstSsrc = audioFirstSsrc;
        this.videoFirstSsrc = videoFirstSsrc;
    }

    public Boolean isEffective() {
        return this.effective;
    }

    public String getSessionId() {
        return this.sessionId;
    }

    public String getIceUfrag() {
        return this.iceUfrag;
    }

    public Long getAudioFirstSsrc() {
        return this.audioFirstSsrc;
    }

    public Long getVideoFirstSsrc() {
        return this.videoFirstSsrc;
    }

    public LongSparseArray<Integer> getSsrcsWithMediaType() {
        return this.ssrcsWithMediaType;
    }

    public SparseArray<SdpMediaCodec> getMediaCodecs() {
        return this.mediaCodecs;
    }

    public void addSsrcWithMediaType(Long ssrc, Integer mediaType) {
        if (ssrc != null) {
            this.ssrcsWithMediaType.put(ssrc.longValue(), mediaType);
        }
    }

    public void addMediaCodecs(Integer id, SdpMediaCodec codec) {
        if (id != null) {
            this.mediaCodecs.put(id.intValue(), codec);
        }
    }

    static SdpStatsIndex create(Boolean effective, String sessionId, String iceUfrag, Long audioFirstSsrc, Long videoFirstSsrc) {
        return new SdpStatsIndex(effective, sessionId, iceUfrag, audioFirstSsrc, videoFirstSsrc);
    }
}
