package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SimulcastLayerConfig {
    private final boolean enable;
    private final long height;
    private final long max_bitrate_kpbs;
    private final long max_framerate;
    private final long min_bitrate_kpbs;
    private final long num_temporal_layers;
    private final boolean start_at_beginning;
    private final long width;

    public SimulcastLayerConfig(long width, long height, long min_bitrate_kpbs, long max_bitrate_kpbs, long max_framerate, long num_temporal_layers, boolean start_at_beginning, boolean enable) {
        this.width = width;
        this.height = height;
        this.min_bitrate_kpbs = min_bitrate_kpbs;
        this.max_bitrate_kpbs = max_bitrate_kpbs;
        this.max_framerate = max_framerate;
        this.num_temporal_layers = num_temporal_layers;
        this.start_at_beginning = start_at_beginning;
        this.enable = enable;
    }

    public long getWidth() {
        return this.width;
    }

    public long getHeight() {
        return this.height;
    }

    public long getMinBitrateKpbs() {
        return this.min_bitrate_kpbs;
    }

    public long getMaxBitrateKpbs() {
        return this.max_bitrate_kpbs;
    }

    public long getMaxFramerate() {
        return this.max_framerate;
    }

    public long getNumTemporalLayers() {
        return this.num_temporal_layers;
    }

    public boolean getStartAtBeginning() {
        return this.start_at_beginning;
    }

    public boolean getEnable() {
        return this.enable;
    }

    static SimulcastLayerConfig create(long width, long height, long min_bitrate_kpbs, long max_bitrate_kpbs, long max_framerate, long num_temporal_layers, boolean start_at_beginning, boolean enable) {
        return new SimulcastLayerConfig(width, height, min_bitrate_kpbs, max_bitrate_kpbs, max_framerate, num_temporal_layers, start_at_beginning, enable);
    }
}
