package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class McsHWDeviceConfig {
    private final String TAG = "McsHWDeviceConfig";

    private native void nativeUpdateConfig(String str);

    public void updateConfig(String config) {
        Logging.d("McsHWDeviceConfig", "update config");
        nativeUpdateConfig(config);
    }
}
