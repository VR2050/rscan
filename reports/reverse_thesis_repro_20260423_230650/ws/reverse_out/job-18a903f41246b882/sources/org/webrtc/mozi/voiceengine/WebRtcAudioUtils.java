package org.webrtc.mozi.voiceengine;

import android.content.Context;
import android.media.AudioDeviceInfo;
import android.media.AudioManager;
import android.os.Build;
import java.util.Arrays;
import java.util.List;
import org.webrtc.mozi.ContextUtils;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public final class WebRtcAudioUtils {
    private static final int DEFAULT_SAMPLE_RATE_HZ = 16000;
    private static final String TAG = "WebRtcAudioUtils";
    private static final String[] BLACKLISTED_OPEN_SL_ES_MODELS = new String[0];
    private static final String[] BLACKLISTED_AEC_MODELS = new String[0];
    private static final String[] BLACKLISTED_NS_MODELS = new String[0];
    private static int defaultSampleRateHz = 16000;
    private static boolean isDefaultSampleRateOverridden = false;
    private static boolean useWebRtcBasedAcousticEchoCanceler = true;
    private static boolean useWebRtcBasedNoiseSuppressor = false;

    public static synchronized void setWebRtcBasedAcousticEchoCanceler(boolean enable) {
        useWebRtcBasedAcousticEchoCanceler = enable;
    }

    public static synchronized void setWebRtcBasedNoiseSuppressor(boolean enable) {
        useWebRtcBasedNoiseSuppressor = enable;
    }

    public static synchronized void setWebRtcBasedAutomaticGainControl(boolean enable) {
        Logging.w(TAG, "setWebRtcBasedAutomaticGainControl() is deprecated");
    }

    public static synchronized boolean useWebRtcBasedAcousticEchoCanceler() {
        if (useWebRtcBasedAcousticEchoCanceler) {
            Logging.w(TAG, "Overriding default behavior; now using WebRTC AEC!");
        }
        return useWebRtcBasedAcousticEchoCanceler;
    }

    public static synchronized boolean useWebRtcBasedNoiseSuppressor() {
        if (useWebRtcBasedNoiseSuppressor) {
            Logging.w(TAG, "Overriding default behavior; now using WebRTC NS!");
        }
        return useWebRtcBasedNoiseSuppressor;
    }

    public static synchronized boolean useWebRtcBasedAutomaticGainControl() {
        return true;
    }

    public static boolean isAcousticEchoCancelerSupported() {
        return WebRtcAudioEffects.canUseAcousticEchoCanceler();
    }

    public static boolean isNoiseSuppressorSupported() {
        return WebRtcAudioEffects.canUseNoiseSuppressor();
    }

    public static boolean isAutomaticGainControlSupported() {
        return false;
    }

    public static synchronized void setDefaultSampleRateHz(int sampleRateHz) {
        isDefaultSampleRateOverridden = true;
        defaultSampleRateHz = sampleRateHz;
    }

    public static synchronized boolean isDefaultSampleRateOverridden() {
        return isDefaultSampleRateOverridden;
    }

    public static synchronized int getDefaultSampleRateHz() {
        return defaultSampleRateHz;
    }

    public static List<String> getBlackListedModelsForAecUsage() {
        return Arrays.asList(BLACKLISTED_AEC_MODELS);
    }

    public static List<String> getBlackListedModelsForNsUsage() {
        return Arrays.asList(BLACKLISTED_NS_MODELS);
    }

    public static boolean runningOnJellyBeanMR1OrHigher() {
        return Build.VERSION.SDK_INT >= 17;
    }

    public static boolean runningOnJellyBeanMR2OrHigher() {
        return Build.VERSION.SDK_INT >= 18;
    }

    public static boolean runningOnLollipopOrHigher() {
        return Build.VERSION.SDK_INT >= 21;
    }

    public static boolean runningOnMarshmallowOrHigher() {
        return Build.VERSION.SDK_INT >= 23;
    }

    public static boolean runningOnNougatOrHigher() {
        return Build.VERSION.SDK_INT >= 24;
    }

    public static boolean runningOnOreoOrHigher() {
        return Build.VERSION.SDK_INT >= 26;
    }

    public static boolean runningOnOreoMR1OrHigher() {
        return Build.VERSION.SDK_INT >= 27;
    }

    public static String getThreadInfo() {
        return "@[name=" + Thread.currentThread().getName() + ", id=" + Thread.currentThread().getId() + "]";
    }

    public static boolean runningOnEmulator() {
        return Build.HARDWARE.equals("goldfish") && Build.BRAND.startsWith("generic_");
    }

    public static boolean deviceIsBlacklistedForOpenSLESUsage() {
        List<String> blackListedModels = Arrays.asList(BLACKLISTED_OPEN_SL_ES_MODELS);
        return blackListedModels.contains(Build.MODEL);
    }

    public static void logDeviceInfo(String tag) {
        Logging.d(tag, "Android SDK: " + Build.VERSION.SDK_INT + ", Release: " + Build.VERSION.RELEASE + ", Brand: " + Build.BRAND + ", Device: " + Build.DEVICE + ", Id: " + Build.ID + ", Hardware: " + Build.HARDWARE + ", Manufacturer: " + Build.MANUFACTURER + ", Model: " + Build.MODEL + ", Product: " + Build.PRODUCT);
    }

    public static void logAudioState(String tag) {
        logDeviceInfo(tag);
        Context context = ContextUtils.getApplicationContext();
        AudioManager audioManager = (AudioManager) context.getSystemService("audio");
        logAudioStateBasic(tag, audioManager);
        logAudioStateVolume(tag, audioManager);
        logAudioDeviceInfo(tag, audioManager);
    }

    private static void logAudioStateBasic(String tag, AudioManager audioManager) {
        Logging.d(tag, "Audio State: audio mode: " + modeToString(audioManager.getMode()) + ", has mic: " + hasMicrophone() + ", mic muted: " + audioManager.isMicrophoneMute() + ", music active: " + audioManager.isMusicActive() + ", speakerphone: " + audioManager.isSpeakerphoneOn() + ", BT SCO: " + audioManager.isBluetoothScoOn());
    }

    private static void logAudioStateVolume(String tag, AudioManager audioManager) {
        int[] streams = {0, 3, 2, 4, 5, 1};
        Logging.d(tag, "Audio State: ");
        boolean fixedVolume = false;
        if (runningOnLollipopOrHigher()) {
            fixedVolume = audioManager.isVolumeFixed();
            Logging.d(tag, "  fixed volume=" + fixedVolume);
        }
        if (!fixedVolume) {
            for (int stream : streams) {
                StringBuilder info = new StringBuilder();
                info.append("  " + streamTypeToString(stream) + ": ");
                info.append("volume=");
                info.append(audioManager.getStreamVolume(stream));
                info.append(", max=");
                info.append(audioManager.getStreamMaxVolume(stream));
                logIsStreamMute(tag, audioManager, stream, info);
                Logging.d(tag, info.toString());
            }
        }
    }

    private static void logIsStreamMute(String tag, AudioManager audioManager, int stream, StringBuilder info) {
        if (runningOnMarshmallowOrHigher()) {
            info.append(", muted=");
            info.append(audioManager.isStreamMute(stream));
        }
    }

    private static void logAudioDeviceInfo(String tag, AudioManager audioManager) {
        AudioDeviceInfo[] devices;
        if (!runningOnMarshmallowOrHigher() || (devices = audioManager.getDevices(3)) == null || devices.length == 0) {
            return;
        }
        Logging.d(tag, "Audio Devices: ");
        for (AudioDeviceInfo device : devices) {
            StringBuilder info = new StringBuilder();
            info.append("  ");
            info.append(deviceTypeToString(device.getType()));
            info.append(device.isSource() ? "(in): " : "(out): ");
            if (device.getChannelCounts().length > 0) {
                info.append("channels=");
                info.append(Arrays.toString(device.getChannelCounts()));
                info.append(", ");
            }
            if (device.getEncodings().length > 0) {
                info.append("encodings=");
                info.append(Arrays.toString(device.getEncodings()));
                info.append(", ");
            }
            if (device.getSampleRates().length > 0) {
                info.append("sample rates=");
                info.append(Arrays.toString(device.getSampleRates()));
                info.append(", ");
            }
            info.append("id=");
            info.append(device.getId());
            Logging.d(tag, info.toString());
        }
    }

    static String modeToString(int mode) {
        if (mode == 0) {
            return "MODE_NORMAL";
        }
        if (mode == 1) {
            return "MODE_RINGTONE";
        }
        if (mode == 2) {
            return "MODE_IN_CALL";
        }
        if (mode == 3) {
            return "MODE_IN_COMMUNICATION";
        }
        return "MODE_INVALID";
    }

    private static String streamTypeToString(int stream) {
        if (stream == 0) {
            return "STREAM_VOICE_CALL";
        }
        if (stream == 1) {
            return "STREAM_SYSTEM";
        }
        if (stream == 2) {
            return "STREAM_RING";
        }
        if (stream == 3) {
            return "STREAM_MUSIC";
        }
        if (stream == 4) {
            return "STREAM_ALARM";
        }
        if (stream == 5) {
            return "STREAM_NOTIFICATION";
        }
        return "STREAM_INVALID";
    }

    private static String deviceTypeToString(int type) {
        switch (type) {
            case 1:
                return "TYPE_BUILTIN_EARPIECE";
            case 2:
                return "TYPE_BUILTIN_SPEAKER";
            case 3:
                return "TYPE_WIRED_HEADSET";
            case 4:
                return "TYPE_WIRED_HEADPHONES";
            case 5:
                return "TYPE_LINE_ANALOG";
            case 6:
                return "TYPE_LINE_DIGITAL";
            case 7:
                return "TYPE_BLUETOOTH_SCO";
            case 8:
                return "TYPE_BLUETOOTH_A2DP";
            case 9:
                return "TYPE_HDMI";
            case 10:
                return "TYPE_HDMI_ARC";
            case 11:
                return "TYPE_USB_DEVICE";
            case 12:
                return "TYPE_USB_ACCESSORY";
            case 13:
                return "TYPE_DOCK";
            case 14:
                return "TYPE_FM";
            case 15:
                return "TYPE_BUILTIN_MIC";
            case 16:
                return "TYPE_FM_TUNER";
            case 17:
                return "TYPE_TV_TUNER";
            case 18:
                return "TYPE_TELEPHONY";
            case 19:
                return "TYPE_AUX_LINE";
            case 20:
                return "TYPE_IP";
            case 21:
                return "TYPE_BUS";
            case 22:
                return "TYPE_USB_HEADSET";
            default:
                return "TYPE_UNKNOWN";
        }
    }

    private static boolean hasMicrophone() {
        return ContextUtils.getApplicationContext().getPackageManager().hasSystemFeature("android.hardware.microphone");
    }
}
