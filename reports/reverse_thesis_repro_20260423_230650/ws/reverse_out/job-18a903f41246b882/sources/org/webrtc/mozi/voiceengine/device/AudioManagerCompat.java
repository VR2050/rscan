package org.webrtc.mozi.voiceengine.device;

import android.content.Context;
import android.media.AudioManager;
import android.os.Build;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.StringUtils;
import org.webrtc.mozi.utils.ThreadExecutor;

/* JADX INFO: loaded from: classes3.dex */
public class AudioManagerCompat {
    private static final int AUDIO_MODE_NORMAL = 0;
    private static final String BRAND_HUAWEI = "HUAWEI";
    private static final String MODEL_HUAWEI_LIO_AL00 = "HWLIO";
    private static final String TAG = "AudioManagerCompat";
    private static boolean sCommunicationEnable = true;

    public static void setCommunicationEnable(boolean communicationEnable) {
        sCommunicationEnable = communicationEnable;
    }

    public static int getMode(AudioManager audioManager) {
        if (audioManager == null) {
            return -2;
        }
        try {
            return audioManager.getMode();
        } catch (Throwable e) {
            Logging.e(TAG, "get audio mode failed: " + e.getMessage());
            return -2;
        }
    }

    public static void setMode(AudioManager audioManager, int mode) {
        setMode(audioManager, mode, true);
    }

    public static void setMode(final AudioManager audioManager, final int mode, boolean async) {
        if (async) {
            ThreadExecutor.execute(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioManagerCompat.1
                @Override // java.lang.Runnable
                public void run() {
                    AudioManagerCompat.setModeInternal(audioManager, mode);
                }
            });
        } else {
            setModeInternal(audioManager, mode);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void setModeInternal(AudioManager audioManager, int mode) {
        if (audioManager == null || mode == -2) {
            return;
        }
        if (mode == 3 && !sCommunicationEnable) {
            Logging.i(TAG, "[setModeInternal] failed: communication mode unable");
            return;
        }
        int presentMode = getMode(audioManager);
        if (presentMode == mode) {
            return;
        }
        try {
            Logging.i(TAG, "AudioManager.setMode: " + mode);
            audioManager.setMode(mode);
            setVolumeBaseOnMode(audioManager, mode);
        } catch (Throwable e) {
            Logging.e(TAG, "set audio mode failed " + e.getMessage());
        }
    }

    private static boolean isNeedSetStreamVolume(int volume) {
        return volume > 0;
    }

    private static void setVolumeBaseOnMode(AudioManager audioManager, int mode) {
        if (audioManager == null || mode == -2) {
            return;
        }
        if (mode == 0) {
            int currentVolume = audioManager.getStreamVolume(3);
            if (isNeedSetStreamVolume(currentVolume)) {
                Logging.i(TAG, "setVolumeBaseOnMode, STREAM_MUSIC, currentVolume=" + currentVolume);
                setStreamVolume(audioManager, 3, currentVolume, 0);
                return;
            }
            return;
        }
        if (mode == 2 || mode == 3) {
            int currentVolume2 = audioManager.getStreamVolume(0);
            if (isNeedSetStreamVolume(currentVolume2)) {
                Logging.i(TAG, "setVolumeBaseOnMode, STREAM_VOICE_CALL, currentVolume=" + currentVolume2);
                setStreamVolume(audioManager, 0, currentVolume2, 0);
            }
        }
    }

    private static void setStreamVolume(AudioManager audioManager, int streamType, int index, int flags) {
        if (audioManager == null) {
            return;
        }
        try {
            audioManager.setStreamVolume(streamType, index, flags);
        } catch (Throwable e) {
            Logging.e(TAG, "setStreamVolume failed: " + e.getMessage());
        }
    }

    static void setSpeakerphoneOn(AudioManager audioManager, boolean speakerOn, boolean isWiredHeadset) {
        if (audioManager == null) {
            return;
        }
        Logging.i(TAG, "setSpeakerphoneOn : " + speakerOn);
        try {
            audioManager.setSpeakerphoneOn(speakerOn);
        } catch (Throwable e) {
            Logging.e(TAG, StringUtils.getAppendString("enableSpeaker failed ", String.valueOf(speakerOn), e.getMessage()));
        }
    }

    private static boolean shouldNotSetMode() {
        return BRAND_HUAWEI.equals(Build.BRAND) && MODEL_HUAWEI_LIO_AL00.equals(Build.DEVICE);
    }

    public static void setSystemMicrophoneMuted(Context context, boolean mute) {
        AudioManager audioManager;
        if (context == null || (audioManager = (AudioManager) context.getSystemService("audio")) == null) {
            return;
        }
        Logging.i(TAG, "setSystemMicrophoneMuted " + mute);
        try {
            audioManager.setMicrophoneMute(mute);
        } catch (Throwable e) {
            Logging.e(TAG, "Failed to setSystemMicrophoneMuted mute: " + mute + ", error: " + e.getMessage());
        }
    }

    public static boolean isSystemMicrophoneMuted(Context context) {
        AudioManager audioManager;
        if (context == null || (audioManager = (AudioManager) context.getSystemService("audio")) == null) {
            return false;
        }
        return audioManager.isMicrophoneMute();
    }
}
