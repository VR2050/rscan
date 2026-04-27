package org.webrtc.mozi.voiceengine.device;

import android.content.Context;
import android.media.AudioManager;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public abstract class AbstractAudioDevice {
    private static final String TAG = "AbstractAudioDevice";
    protected AudioManager mAudioManager;
    protected AudioRouteType mAudioRouteType;
    protected Context mContext;
    protected DeviceDeactivateCallback mDeviceDeactivateCallback;

    public interface ActivateCallback {
        void onActivateFail();

        void onActivateSuccess(AbstractAudioDevice abstractAudioDevice);
    }

    public interface DeviceDeactivateCallback {
        void onDeactivateDevice(AbstractAudioDevice abstractAudioDevice);
    }

    public abstract void activate(ActivateCallback activateCallback);

    public abstract void checkAndReactivate();

    public abstract String getName();

    public abstract void inactivate();

    public AbstractAudioDevice(Context context, AudioRouteType audioRouteType) {
        this.mContext = context;
        this.mAudioRouteType = audioRouteType;
        this.mAudioManager = (AudioManager) context.getSystemService("audio");
    }

    public void setDeviceDeactivateCallback(DeviceDeactivateCallback deviceDeactivateCallback) {
        this.mDeviceDeactivateCallback = deviceDeactivateCallback;
    }

    public void onDeviceDeactivate() {
        DeviceDeactivateCallback deviceDeactivateCallback = this.mDeviceDeactivateCallback;
        if (deviceDeactivateCallback != null) {
            deviceDeactivateCallback.onDeactivateDevice(this);
        }
    }

    public boolean isEnabled() {
        return true;
    }

    public int getPreferAudioMode() {
        return 3;
    }

    public AudioRouteType getAudioRouteType() {
        return this.mAudioRouteType;
    }

    protected void enableSpeaker(boolean enable) {
        try {
            if (enable) {
                this.mAudioManager.setSpeakerphoneOn(true);
            } else {
                this.mAudioManager.setSpeakerphoneOn(false);
            }
        } catch (Throwable e) {
            Logging.e(TAG, "enableSpeaker failed, enable=" + String.valueOf(enable) + " " + e.getMessage());
        }
    }
}
