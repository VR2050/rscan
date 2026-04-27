package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SimulcastConfigHelper {
    private final long mcs_config_ptr;

    private native String nativeGetFirstVideoTrackIdFromSessionDescription(long j, String str, String str2);

    private native String nativeSimulcastStream2String(long j, String str);

    private native String nativeSimulcastSubscription2String(long j);

    public SimulcastConfigHelper(long mcs_config_ptr) {
        this.mcs_config_ptr = mcs_config_ptr;
    }

    public String simulcastStream2String(String id) {
        return nativeSimulcastStream2String(this.mcs_config_ptr, id);
    }

    public String simulcastSubscription2String() {
        return nativeSimulcastSubscription2String(this.mcs_config_ptr);
    }

    public String getFirstVideoTrackIdFromSessionDescription(String type, String desc) {
        return nativeGetFirstVideoTrackIdFromSessionDescription(this.mcs_config_ptr, type, desc);
    }
}
