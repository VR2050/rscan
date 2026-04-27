package org.webrtc.mozi.voiceengine.device;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.text.TextUtils;
import im.uwrkaxlmjj.messenger.voip.VoIPBaseService;

/* JADX INFO: loaded from: classes3.dex */
public class WiredHeadsetDetector extends AbstractAudioDeviceDetector {
    private static final String INTENT_KEY_STATE = "state";
    private static final int STATE_ON = 1;
    private AudioManager mAudioManager;
    private Context mContext;
    private WiredHeadsetDevice mHeadsetDevice;
    private AVHeadsetReceiver mHeadsetReceiver;

    public WiredHeadsetDetector(Context context) {
        super(AudioRouteType.WiredHeadset);
        this.mContext = context;
        this.mAudioManager = (AudioManager) context.getSystemService("audio");
        this.mHeadsetDevice = new WiredHeadsetDevice(context);
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector
    public void startDetect() {
        if (this.mHeadsetReceiver == null) {
            this.mHeadsetReceiver = new AVHeadsetReceiver();
        }
        IntentFilter headsetFilter = new IntentFilter(VoIPBaseService.ACTION_HEADSET_PLUG);
        this.mContext.registerReceiver(this.mHeadsetReceiver, headsetFilter);
        if (this.mAudioManager.isWiredHeadsetOn()) {
            onDeviceAvailable(this.mHeadsetDevice);
        } else {
            onDeviceUnavailable(this.mHeadsetDevice);
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector
    public void stopDetect() {
        AVHeadsetReceiver aVHeadsetReceiver = this.mHeadsetReceiver;
        if (aVHeadsetReceiver != null) {
            this.mContext.unregisterReceiver(aVHeadsetReceiver);
        }
    }

    class AVHeadsetReceiver extends BroadcastReceiver {
        AVHeadsetReceiver() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if (intent != null && TextUtils.equals(intent.getAction(), VoIPBaseService.ACTION_HEADSET_PLUG) && intent.hasExtra("state")) {
                int state = intent.getIntExtra("state", 0);
                if (state == 1) {
                    WiredHeadsetDetector wiredHeadsetDetector = WiredHeadsetDetector.this;
                    wiredHeadsetDetector.onDeviceAvailable(wiredHeadsetDetector.mHeadsetDevice);
                } else {
                    WiredHeadsetDetector wiredHeadsetDetector2 = WiredHeadsetDetector.this;
                    wiredHeadsetDetector2.onDeviceUnavailable(wiredHeadsetDetector2.mHeadsetDevice);
                }
            }
        }
    }
}
