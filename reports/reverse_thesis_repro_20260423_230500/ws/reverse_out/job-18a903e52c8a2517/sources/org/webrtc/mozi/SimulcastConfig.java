package org.webrtc.mozi;

import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class SimulcastConfig {
    public static final int K_LOCAL_SIMULCAST_VERSION = 10;
    private final List<SimulcastLayerConfig> camera_bitrate_table;
    private final List<SimulcastLayerConfig> camera_layer;
    private final long lowest_valid_version;
    private final long mcs_config_ptr;
    private final List<SimulcastLayerConfig> screen_bitrate_table;
    private final List<SimulcastLayerConfig> screen_layer;

    private native void nativeVerifySourceResolution(long j, long j2, long j3, boolean z);

    private native void nativeVerifyVideoEncoderCapacity(long j, boolean z, boolean z2);

    public SimulcastConfig(List<SimulcastLayerConfig> camera_bitrate_table, List<SimulcastLayerConfig> screen_bitrate_table, List<SimulcastLayerConfig> camera_layer, List<SimulcastLayerConfig> screen_layer, long lowest_valid_version, long mcs_config_ptr) {
        this.camera_bitrate_table = camera_bitrate_table;
        this.screen_bitrate_table = screen_bitrate_table;
        this.camera_layer = camera_layer;
        this.screen_layer = screen_layer;
        this.lowest_valid_version = lowest_valid_version;
        this.mcs_config_ptr = mcs_config_ptr;
    }

    public List<SimulcastLayerConfig> getCameraBitrateTable() {
        return this.camera_bitrate_table;
    }

    public List<SimulcastLayerConfig> getScreenBitrateTable() {
        return this.screen_bitrate_table;
    }

    public List<SimulcastLayerConfig> getCameraLayer() {
        return this.camera_layer;
    }

    public List<SimulcastLayerConfig> getScreenLayer() {
        return this.screen_layer;
    }

    public long getLowestValidVersion() {
        return this.lowest_valid_version;
    }

    public boolean isSimulcastEnabled() {
        List<SimulcastLayerConfig> list;
        List<SimulcastLayerConfig> list2 = this.camera_layer;
        return ((list2 == null || list2.isEmpty()) && ((list = this.screen_layer) == null || list.isEmpty())) ? false : true;
    }

    public void verifySourcewResolution(long width, long height, boolean isScreen) {
        nativeVerifySourceResolution(this.mcs_config_ptr, width, height, isScreen);
    }

    public void verifyVideoEncoderCapacity(boolean isOnePCenable, boolean supportSimulcast) {
        nativeVerifyVideoEncoderCapacity(this.mcs_config_ptr, isOnePCenable, supportSimulcast);
    }

    static SimulcastConfig create(List<SimulcastLayerConfig> camera_bitrate_table, List<SimulcastLayerConfig> screen_bitrate_table, List<SimulcastLayerConfig> camera_layer, List<SimulcastLayerConfig> screen_layer, long lowest_valid_version, long mcs_config_ptr) {
        return new SimulcastConfig(camera_bitrate_table, screen_bitrate_table, camera_layer, screen_layer, lowest_valid_version, mcs_config_ptr);
    }
}
