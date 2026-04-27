package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class GeneralSimulcastConfig {
    private final boolean allow_non_simulcast_request;
    private final long lowest_valid_version;
    private final float screen_request_ratio;
    private final long screen_temporal_layer_num;
    private final long simulcast_layer_num;
    private final long temporal_layer_num;

    public GeneralSimulcastConfig(long simulcast_layer_num, long temporal_layer_num, long screen_temporal_layer_num, boolean allow_non_simulcast_request, float screen_request_ratio, long lowest_valid_version) {
        this.simulcast_layer_num = simulcast_layer_num;
        this.temporal_layer_num = temporal_layer_num;
        this.screen_temporal_layer_num = screen_temporal_layer_num;
        this.allow_non_simulcast_request = allow_non_simulcast_request;
        this.screen_request_ratio = screen_request_ratio;
        this.lowest_valid_version = lowest_valid_version;
    }

    public long getSimulcastLayerNum() {
        return this.simulcast_layer_num;
    }

    public long getTemporalLayerNum() {
        return this.temporal_layer_num;
    }

    public long getScreenTemporalLayerNum() {
        return this.screen_temporal_layer_num;
    }

    public boolean getAllowNonSimulcastRequest() {
        return this.allow_non_simulcast_request;
    }

    public float getScreenRequestRatio() {
        return this.screen_request_ratio;
    }

    public long getLowestValidVersion() {
        return this.lowest_valid_version;
    }

    static GeneralSimulcastConfig create(long simulcast_layer_num, long temporal_layer_num, long screen_temporal_layer_num, boolean allow_non_simulcast_request, float screen_request_ratio, long lowest_valid_version) {
        return new GeneralSimulcastConfig(simulcast_layer_num, temporal_layer_num, screen_temporal_layer_num, allow_non_simulcast_request, screen_request_ratio, lowest_valid_version);
    }
}
