package org.webrtc.mozi.voiceengine.device;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import com.litesuits.orm.db.assit.SQLBuilder;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public class AudioVolumeMonitor {
    private static final String TAG = "AudioVolumeMonitor";
    private Context mContext = null;
    private AudioManager mAudioManager = null;
    private VolumeBroadcastReceiver mVolumeBroadcastReceiver = null;
    private int mCurrentMediaVolume = 0;
    private int mMaxMediaVolume = 0;
    private int mCurrentVoiceCallVolume = 0;
    private int mMaxVoiceCallVolume = 0;
    private boolean mInitialize = false;

    private class VolumeBroadcastReceiver extends BroadcastReceiver {
        private VolumeBroadcastReceiver() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            AudioVolumeMonitor.this.onAudioVolumeChanged();
        }
    }

    public void onAudioVolumeChanged() {
        try {
            int mediaVolume = getStreamVolume(3);
            int voiceCallVolume = getStreamVolume(0);
            if (this.mCurrentMediaVolume != mediaVolume || this.mCurrentVoiceCallVolume != voiceCallVolume) {
                Logging.i(TAG, "onAudioVolumeChanged, mediaVolume:(" + mediaVolume + " / " + this.mMaxMediaVolume + "), voiceCallVolume:(" + voiceCallVolume + " / " + this.mMaxVoiceCallVolume + SQLBuilder.PARENTHESES_RIGHT);
                this.mCurrentMediaVolume = mediaVolume;
                this.mCurrentVoiceCallVolume = voiceCallVolume;
            }
        } catch (Exception e) {
            Logging.e(TAG, "onAudioVolumeChanged, get volume error: " + e.getMessage());
        }
    }

    public void init(Context context) {
        if (this.mInitialize) {
            return;
        }
        this.mContext = context;
        AudioManager audioManager = (AudioManager) context.getSystemService("audio");
        this.mAudioManager = audioManager;
        this.mMaxMediaVolume = audioManager.getStreamMaxVolume(3);
        this.mMaxVoiceCallVolume = this.mAudioManager.getStreamMaxVolume(0);
        this.mInitialize = true;
    }

    public void startMonitor() {
        Logging.i(TAG, "start monitor audio volume");
        if (!this.mInitialize) {
            return;
        }
        try {
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction("android.media.VOLUME_CHANGED_ACTION");
            VolumeBroadcastReceiver volumeBroadcastReceiver = new VolumeBroadcastReceiver();
            this.mVolumeBroadcastReceiver = volumeBroadcastReceiver;
            registerReceiver(volumeBroadcastReceiver, intentFilter);
        } catch (Exception e) {
            Logging.e(TAG, "start monitor audio volume error: " + e.getMessage());
        }
    }

    public void stopMonitor() {
        Logging.i(TAG, "stop monitor audio volume");
        if (!this.mInitialize) {
            return;
        }
        try {
            if (this.mVolumeBroadcastReceiver != null) {
                unRegisterReceiver(this.mVolumeBroadcastReceiver);
                this.mVolumeBroadcastReceiver = null;
            }
        } catch (Exception e) {
            Logging.e(TAG, "stop monitor audio volume error: " + e.getMessage());
        }
    }

    public void destroy() {
        if (!this.mInitialize) {
            return;
        }
        this.mContext = null;
        this.mAudioManager = null;
        this.mInitialize = false;
    }

    private void registerReceiver(BroadcastReceiver receiver, IntentFilter filter) {
        Context context = this.mContext;
        if (context != null) {
            context.registerReceiver(receiver, filter);
        }
    }

    private void unRegisterReceiver(BroadcastReceiver receiver) {
        Context context = this.mContext;
        if (context != null) {
            context.unregisterReceiver(receiver);
        }
    }

    private int getStreamVolume(int streamType) {
        AudioManager audioManager = this.mAudioManager;
        if (audioManager != null) {
            return audioManager.getStreamVolume(streamType);
        }
        return -1;
    }
}
