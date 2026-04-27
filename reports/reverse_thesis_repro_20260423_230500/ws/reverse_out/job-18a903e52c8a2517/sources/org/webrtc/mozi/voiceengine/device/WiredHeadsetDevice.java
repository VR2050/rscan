package org.webrtc.mozi.voiceengine.device;

import android.content.Context;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.voiceengine.device.AbstractAudioDevice;

/* JADX INFO: loaded from: classes3.dex */
public class WiredHeadsetDevice extends AbstractAudioDevice {
    private static final String TAG = "WiredHeadsetDevice";

    public WiredHeadsetDevice(Context context) {
        super(context, AudioRouteType.WiredHeadset);
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void activate(AbstractAudioDevice.ActivateCallback activateCallback) {
        if (activateCallback != null) {
            activateCallback.onActivateSuccess(this);
        }
        AudioManagerCompat.setSpeakerphoneOn(this.mAudioManager, false, true);
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void inactivate() {
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void checkAndReactivate() {
        try {
            int audioMode = this.mAudioManager.getMode();
            boolean isSpeakerPhoneOn = this.mAudioManager.isSpeakerphoneOn();
            boolean isScoOn = this.mAudioManager.isBluetoothScoOn();
            Logging.i(TAG, "current audioMode: " + audioMode + ", isSpeakerPhoneOn: " + isSpeakerPhoneOn + ", scoOn: " + isScoOn);
            if (audioMode != getPreferAudioMode()) {
                this.mAudioManager.setMode(getPreferAudioMode());
            }
            if (isScoOn) {
                this.mAudioManager.stopBluetoothSco();
                this.mAudioManager.setBluetoothScoOn(false);
            }
            if (isSpeakerPhoneOn) {
                inactivate();
                activate(null);
            }
        } catch (Exception e) {
            Logging.e(TAG, "checkAndReactivate error:" + e.getMessage());
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public String getName() {
        return "headphone";
    }
}
