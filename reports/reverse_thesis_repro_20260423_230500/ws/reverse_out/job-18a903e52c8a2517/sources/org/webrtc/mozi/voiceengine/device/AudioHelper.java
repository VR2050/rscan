package org.webrtc.mozi.voiceengine.device;

import android.content.Context;
import android.media.AudioManager;
import android.media.AudioRecordingConfiguration;
import android.os.Build;
import android.os.Process;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public class AudioHelper {
    private static final String TAG = "AudioHelper";

    public static class RecordAppInfo {
        String packageName;
        int session;
        int source;

        public String toString() {
            return "RecordAppInfo{packageName='" + this.packageName + "', source=" + this.source + ", session=" + this.session + '}';
        }
    }

    public static List<RecordAppInfo> getRecordingAppInfo(Context context) {
        AudioManager audioManager;
        List<RecordAppInfo> recordAppInfos = new LinkedList<>();
        if (context != null && (audioManager = (AudioManager) context.getSystemService("audio")) != null && Build.VERSION.SDK_INT >= 24) {
            try {
                List<AudioRecordingConfiguration> audioRecordingConfigurations = audioManager.getActiveRecordingConfigurations();
                if (audioRecordingConfigurations != null) {
                    for (AudioRecordingConfiguration configuration : audioRecordingConfigurations) {
                        recordAppInfos.add(convertRecordAppInfo(configuration));
                    }
                }
            } catch (Exception e) {
                Logging.e(TAG, "failed to getActiveRecordingConfigurations " + e.getMessage());
            }
        }
        return recordAppInfos;
    }

    private static RecordAppInfo convertRecordAppInfo(AudioRecordingConfiguration configuration) {
        RecordAppInfo recordAppInfo = new RecordAppInfo();
        if (Build.VERSION.SDK_INT > 23) {
            recordAppInfo.source = configuration.getClientAudioSource();
            recordAppInfo.session = configuration.getClientAudioSessionId();
        }
        try {
            Field field = configuration.getClass().getDeclaredField("mClientPackageName");
            field.setAccessible(true);
            recordAppInfo.packageName = (String) field.get(configuration);
        } catch (Exception e) {
            Logging.e(TAG, "failed to convertRecordAppInfo: " + e.getMessage());
        }
        return recordAppInfo;
    }

    private static boolean hasPermission(Context context, String permission) {
        return context.checkPermission(permission, Process.myPid(), Process.myUid()) == 0;
    }

    public static boolean hasAudioRecordPermission(Context context) {
        return hasPermission(context, "android.permission.RECORD_AUDIO");
    }

    public static boolean hasBluetoothPermission(Context context) {
        return hasPermission(context, "android.permission.BLUETOOTH");
    }

    public static boolean hasPhoneStatePermission(Context context) {
        return hasPermission(context, "android.permission.READ_PHONE_STATE");
    }

    public static String audioFocusToString(int audioFocus) {
        if (audioFocus == -3) {
            return "AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK";
        }
        if (audioFocus == -2) {
            return "AUDIOFOCUS_LOSS_TRANSIENT";
        }
        if (audioFocus == -1) {
            return "AUDIOFOCUS_LOSS";
        }
        if (audioFocus == 1) {
            return "AUDIOFOCUS_GAIN";
        }
        if (audioFocus == 2) {
            return "AUDIOFOCUS_GAIN_TRANSIENT";
        }
        if (audioFocus == 3) {
            return "AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK";
        }
        if (audioFocus == 4) {
            return "AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE";
        }
        return "AUDIOFOCUS_NOT_DEFINED";
    }

    public static String phoneStateToString(int phoneState) {
        if (phoneState == 0) {
            return "CALL_STATE_IDLE";
        }
        if (phoneState == 1) {
            return "CALL_STATE_RINGING";
        }
        if (phoneState == 2) {
            return "CALL_STATE_OFFHOOK";
        }
        return "CALL_STATE__NOT_DEFINED";
    }
}
