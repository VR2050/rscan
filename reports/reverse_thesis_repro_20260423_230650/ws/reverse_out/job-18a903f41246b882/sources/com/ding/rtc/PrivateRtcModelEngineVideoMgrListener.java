package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
interface PrivateRtcModelEngineVideoMgrListener {
    void onVideoDeviceChanged(int type, int state);

    void onVideoDeviceEventTracking(String module, int code, String desc, String attr);

    void onVideoDeviceException(int type, String deviceId, String deviceName);
}
