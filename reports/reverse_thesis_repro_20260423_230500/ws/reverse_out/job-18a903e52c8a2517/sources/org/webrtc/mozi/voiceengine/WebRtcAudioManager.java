package org.webrtc.mozi.voiceengine;

import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.os.Build;
import com.litesuits.orm.db.assit.SQLBuilder;
import java.util.Timer;
import java.util.TimerTask;
import javax.annotation.Nullable;
import org.webrtc.mozi.CodecMonitorHelper;
import org.webrtc.mozi.ContextUtils;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.McsConfigHelper;
import org.webrtc.mozi.McsHWDeviceHelper;
import org.webrtc.mozi.voiceengine.device.AudioDeviceManager;
import org.webrtc.mozi.voiceengine.device.AudioHelper;
import org.webrtc.mozi.voiceengine.device.AudioRouteType;

/* JADX INFO: loaded from: classes3.dex */
public class WebRtcAudioManager {
    private static final int BITS_PER_SAMPLE = 16;
    private static final boolean DEBUG = false;
    private static final int DEFAULT_FRAME_PER_BUFFER = 256;
    private static final String TAG = "WebRtcAudioManager";
    private static final boolean blacklistDeviceForAAudioUsage = true;
    private static final int kAliRtcAudioRouteType_BlueTooth = 6;
    private static final int kAliRtcAudioRouteType_Default = 0;
    private static final int kAliRtcAudioRouteType_Earpiece = 2;
    private static final int kAliRtcAudioRouteType_Headset = 1;
    private static final int kAliRtcAudioRouteType_HeadsetNoMic = 3;
    private static final int kAliRtcAudioRouteType_LoudSpeaker = 5;
    private static final int kAliRtcAudioRouteType_Speakerphone = 4;
    private boolean aAudio;
    private final AudioManager audioManager;
    private boolean hardwareAEC;
    private boolean hardwareAGC;
    private boolean hardwareNS;
    private int inputBufferSize;
    private int inputChannels;
    private boolean lowLatencyInput;
    private boolean lowLatencyOutput;
    private final long nativeAudioManager;
    private int nativeChannels;
    private int nativeSampleRate;
    private int outputBufferSize;
    private int outputChannels;
    private boolean proAudio;
    private int sampleRate;
    private final VolumeLogger volumeLogger;
    private static boolean useStereoOutput = false;
    private static boolean useStereoInput = false;
    private static boolean blacklistDeviceForOpenSLESUsage = false;
    private static boolean blacklistDeviceForOpenSLESUsageIsOverridden = false;
    public static int sMode = 3;
    private boolean initialized = false;
    private McsConfigHelper configHelper = new McsConfigHelper(0);
    private AudioDeviceManager audioDeviceManager = null;
    private AudioDeviceManager.AudioDeviceManagerListener audioDeviceManagerListener = null;
    private boolean audioDeviceManagerAndroid = false;
    private boolean enableGeneralAudioOpt = false;
    private boolean enableAudioRouteOpt = false;
    private boolean isDefaultToSpeakerphone = true;
    private boolean isEnableSpeakerphone = true;

    private native void nativeCacheAudioParameters(int i, int i2, int i3, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, int i4, int i5, long j);

    /* JADX INFO: Access modifiers changed from: private */
    public native void nativeOnAudioFocusChanged(long j, int i);

    /* JADX INFO: Access modifiers changed from: private */
    public native void nativeOnAudioInterrupted(long j, boolean z);

    /* JADX INFO: Access modifiers changed from: private */
    public native void nativeOnAudioRouteChanged(long j, int i);

    public static synchronized void setBlacklistDeviceForOpenSLESUsage(boolean enable) {
        blacklistDeviceForOpenSLESUsageIsOverridden = true;
        blacklistDeviceForOpenSLESUsage = enable;
    }

    public static synchronized void setStereoOutput(boolean enable) {
        Logging.w(TAG, "Overriding default output behavior: setStereoOutput(" + enable + ')');
        useStereoOutput = enable;
    }

    public static synchronized void setStereoInput(boolean enable) {
        Logging.w(TAG, "Overriding default input behavior: setStereoInput(" + enable + ')');
        useStereoInput = enable;
    }

    public static synchronized boolean getStereoOutput() {
        return useStereoOutput;
    }

    public static synchronized boolean getStereoInput() {
        return useStereoInput;
    }

    private static class VolumeLogger {
        private static final String THREAD_NAME = "WebRtcVolumeLevelLoggerThread";
        private static final int TIMER_PERIOD_IN_SECONDS = 30;
        private final AudioManager audioManager;

        @Nullable
        private Timer timer;

        public VolumeLogger(AudioManager audioManager) {
            this.audioManager = audioManager;
        }

        public void start() {
            Timer timer = new Timer(THREAD_NAME);
            this.timer = timer;
            timer.schedule(new LogVolumeTask(this.audioManager.getStreamMaxVolume(2), this.audioManager.getStreamMaxVolume(0)), 0L, 30000L);
        }

        private class LogVolumeTask extends TimerTask {
            private final int maxRingVolume;
            private final int maxVoiceCallVolume;

            LogVolumeTask(int maxRingVolume, int maxVoiceCallVolume) {
                this.maxRingVolume = maxRingVolume;
                this.maxVoiceCallVolume = maxVoiceCallVolume;
            }

            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                try {
                    int mode = VolumeLogger.this.audioManager.getMode();
                    if (mode == 1) {
                        Logging.d(WebRtcAudioManager.TAG, "STREAM_RING stream volume: " + VolumeLogger.this.audioManager.getStreamVolume(2) + " (max=" + this.maxRingVolume + SQLBuilder.PARENTHESES_RIGHT);
                        return;
                    }
                    if (mode == 3) {
                        Logging.d(WebRtcAudioManager.TAG, "VOICE_CALL stream volume: " + VolumeLogger.this.audioManager.getStreamVolume(0) + " (max=" + this.maxVoiceCallVolume + SQLBuilder.PARENTHESES_RIGHT);
                    }
                } catch (Throwable e) {
                    Logging.e(WebRtcAudioManager.TAG, "audioManager.getMode failed", e);
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void stop() {
            Timer timer = this.timer;
            if (timer != null) {
                timer.cancel();
                this.timer = null;
            }
        }
    }

    WebRtcAudioManager(long nativeAudioManager) {
        Logging.d(TAG, "ctor" + WebRtcAudioUtils.getThreadInfo());
        this.nativeAudioManager = nativeAudioManager;
        AudioManager audioManager = (AudioManager) ContextUtils.getApplicationContext().getSystemService("audio");
        this.audioManager = audioManager;
        this.volumeLogger = new VolumeLogger(audioManager);
        WebRtcAudioUtils.logAudioState(TAG);
    }

    private void updateOneRTCAudioConfig() {
        this.audioDeviceManagerAndroid = this.configHelper.getOneRTCAudioConfig().getAudioDeviceManagerAndroid();
        this.enableGeneralAudioOpt = this.configHelper.getOneRTCAudioConfig().getGeneralAudioOpt();
        this.enableAudioRouteOpt = this.configHelper.getOneRTCAudioConfig().getAudioRouteOpt();
        Logging.i(TAG, "OneRTCAudioConfig, audioDeviceManagerAndroid: " + this.audioDeviceManagerAndroid + ", enableGeneralAudioOpt: " + this.enableGeneralAudioOpt + ", enableAudioRouteOpt: " + this.enableAudioRouteOpt);
    }

    private boolean init() {
        Logging.d(TAG, CodecMonitorHelper.EVENT_INIT + WebRtcAudioUtils.getThreadInfo());
        if (this.initialized) {
            return true;
        }
        updateOneRTCAudioConfig();
        if (!this.enableAudioRouteOpt) {
            startAudioRouteManager();
        }
        Logging.d(TAG, "audio mode is: " + WebRtcAudioUtils.modeToString(this.audioManager.getMode()));
        this.initialized = true;
        this.volumeLogger.start();
        return true;
    }

    private void dispose() {
        Logging.d(TAG, "dispose" + WebRtcAudioUtils.getThreadInfo());
        if (!this.initialized) {
            return;
        }
        if (!this.enableAudioRouteOpt) {
            stopAudioRouteManager();
        }
        this.volumeLogger.stop();
    }

    private void prepare() {
        Logging.d(TAG, "prepare" + WebRtcAudioUtils.getThreadInfo());
        if (!this.initialized) {
            return;
        }
        WebRtcAudioUtils.logAudioState(TAG);
        if (this.enableAudioRouteOpt) {
            startAudioRouteManager();
        }
    }

    private void clearup() {
        Logging.d(TAG, "clearup" + WebRtcAudioUtils.getThreadInfo());
        if (this.initialized && this.enableAudioRouteOpt) {
            stopAudioRouteManager();
        }
    }

    private void startAudioRouteManager() {
        if (this.audioDeviceManagerAndroid) {
            Logging.i(TAG, "startAudioRouteManager");
            if (this.audioDeviceManagerListener == null) {
                this.audioDeviceManagerListener = new AudioDeviceManager.AudioDeviceManagerListener() { // from class: org.webrtc.mozi.voiceengine.WebRtcAudioManager.1
                    @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceManager.AudioDeviceManagerListener
                    public void onAudioRouteChanged(AudioRouteType audioRoute) {
                        WebRtcAudioManager webRtcAudioManager = WebRtcAudioManager.this;
                        webRtcAudioManager.nativeOnAudioRouteChanged(webRtcAudioManager.nativeAudioManager, WebRtcAudioManager.convertFromJavaAudioRoute(audioRoute));
                    }

                    @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceManager.AudioDeviceManagerListener
                    public void onAudioFocusChanged(int focusChanged) {
                        WebRtcAudioManager webRtcAudioManager = WebRtcAudioManager.this;
                        webRtcAudioManager.nativeOnAudioFocusChanged(webRtcAudioManager.nativeAudioManager, focusChanged);
                    }

                    @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceManager.AudioDeviceManagerListener
                    public void onAudioInterrupted(boolean interrupted) {
                        WebRtcAudioManager webRtcAudioManager = WebRtcAudioManager.this;
                        webRtcAudioManager.nativeOnAudioInterrupted(webRtcAudioManager.nativeAudioManager, interrupted);
                    }
                };
            }
            if (this.audioDeviceManager == null) {
                AudioDeviceManager audioDeviceManager = new AudioDeviceManager(this.enableGeneralAudioOpt);
                this.audioDeviceManager = audioDeviceManager;
                audioDeviceManager.init(ContextUtils.getApplicationContext());
                this.audioDeviceManager.setAudioDeviceManagerListener(this.audioDeviceManagerListener);
                this.audioDeviceManager.setDefaultAudioRouteToSpeakerphone(this.isDefaultToSpeakerphone);
                this.audioDeviceManager.enableSpeakerphone(this.isEnableSpeakerphone);
            }
        }
    }

    private void stopAudioRouteManager() {
        if (this.audioDeviceManagerAndroid) {
            Logging.i(TAG, "stopAudioRouteManager");
            AudioDeviceManager audioDeviceManager = this.audioDeviceManager;
            if (audioDeviceManager != null) {
                audioDeviceManager.setAudioDeviceManagerListener(null);
                this.audioDeviceManager.destroy();
                this.audioDeviceManager = null;
            }
            if (this.audioDeviceManagerListener != null) {
                this.audioDeviceManagerListener = null;
            }
        }
    }

    private boolean isCommunicationModeEnabled() {
        return this.audioManager.getMode() == 3;
    }

    private boolean isDeviceBlacklistedForOpenSLESUsage() {
        boolean blacklisted = blacklistDeviceForOpenSLESUsageIsOverridden ? blacklistDeviceForOpenSLESUsage : WebRtcAudioUtils.deviceIsBlacklistedForOpenSLESUsage();
        if (blacklisted) {
            Logging.d(TAG, Build.MODEL + " is blacklisted for OpenSL ES usage!");
        }
        return blacklisted;
    }

    private void setMode(int mode) {
        AudioManager audioManager = this.audioManager;
        if (audioManager != null) {
            if (audioManager.isSpeakerphoneOn()) {
                this.audioManager.setMode(mode);
                sMode = mode;
            } else {
                this.audioManager.setMode(3);
                sMode = 3;
            }
        }
    }

    private void loadAudioParameters() {
        storeAudioParameters();
        nativeCacheAudioParameters(this.sampleRate, this.outputChannels, this.inputChannels, this.hardwareAEC, this.hardwareAGC, this.hardwareNS, this.lowLatencyOutput, this.lowLatencyInput, this.proAudio, this.aAudio, this.outputBufferSize, this.inputBufferSize, this.nativeAudioManager);
    }

    private void storeAudioParameters() {
        this.outputChannels = getStereoOutput() ? 2 : 1;
        this.inputChannels = getStereoInput() ? 2 : 1;
        this.sampleRate = getNativeOutputSampleRate();
        this.hardwareAEC = isAcousticEchoCancelerSupported();
        this.hardwareAGC = false;
        this.hardwareNS = isNoiseSuppressorSupported();
        this.lowLatencyOutput = isLowLatencyOutputSupported();
        this.lowLatencyInput = isLowLatencyInputSupported();
        this.proAudio = isProAudioSupported();
        this.aAudio = isAAudioSupported();
        this.outputBufferSize = this.lowLatencyOutput ? getLowLatencyOutputFramesPerBuffer() : getMinOutputFrameSize(this.sampleRate, this.outputChannels);
        this.inputBufferSize = this.lowLatencyInput ? getLowLatencyInputFramesPerBuffer() : getMinInputFrameSize(this.sampleRate, this.inputChannels);
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.voiceengine.WebRtcAudioManager$2, reason: invalid class name */
    static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType;

        static {
            int[] iArr = new int[AudioRouteType.values().length];
            $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType = iArr;
            try {
                iArr[AudioRouteType.Speakerphone.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.Earpiece.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.WiredHeadset.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.Bluetooth.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[AudioRouteType.A2dp.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int convertFromJavaAudioRoute(AudioRouteType javaAudioRoute) {
        int i = AnonymousClass2.$SwitchMap$org$webrtc$mozi$voiceengine$device$AudioRouteType[javaAudioRoute.ordinal()];
        if (i == 1) {
            return 4;
        }
        if (i == 2) {
            return 2;
        }
        if (i == 3) {
            return 1;
        }
        if (i != 4 && i != 5) {
            return 0;
        }
        return 6;
    }

    private static AudioRouteType convertToJavaAudioRoute(int audioRoute) {
        AudioRouteType javaAudioRoute = AudioRouteType.None;
        if (audioRoute == 1) {
            AudioRouteType javaAudioRoute2 = AudioRouteType.WiredHeadset;
            return javaAudioRoute2;
        }
        if (audioRoute == 2) {
            AudioRouteType javaAudioRoute3 = AudioRouteType.Earpiece;
            return javaAudioRoute3;
        }
        if (audioRoute == 4) {
            AudioRouteType javaAudioRoute4 = AudioRouteType.Speakerphone;
            return javaAudioRoute4;
        }
        if (audioRoute == 6) {
            AudioRouteType javaAudioRoute5 = AudioRouteType.Bluetooth;
            return javaAudioRoute5;
        }
        return javaAudioRoute;
    }

    private int setDefaultAudioRouteToSpeakerphone(boolean defaultToSpeaker) {
        AudioDeviceManager audioDeviceManager = this.audioDeviceManager;
        if (audioDeviceManager != null) {
            return audioDeviceManager.setDefaultAudioRouteToSpeakerphone(defaultToSpeaker);
        }
        this.isDefaultToSpeakerphone = defaultToSpeaker;
        return 0;
    }

    private int enableSpeakerphone(boolean enable) {
        AudioDeviceManager audioDeviceManager = this.audioDeviceManager;
        if (audioDeviceManager != null) {
            return audioDeviceManager.enableSpeakerphone(enable);
        }
        this.isEnableSpeakerphone = enable;
        return 0;
    }

    private boolean isSpeakerphoneEnabled() {
        AudioDeviceManager audioDeviceManager = this.audioDeviceManager;
        if (audioDeviceManager != null) {
            return audioDeviceManager.isSpeakerphoneEnabled();
        }
        return false;
    }

    private boolean hasEarpiece() {
        return ContextUtils.getApplicationContext().getPackageManager().hasSystemFeature("android.hardware.telephony");
    }

    private boolean isLowLatencyOutputSupported() {
        return ContextUtils.getApplicationContext().getPackageManager().hasSystemFeature("android.hardware.audio.low_latency");
    }

    public boolean isLowLatencyInputSupported() {
        return WebRtcAudioUtils.runningOnLollipopOrHigher() && isLowLatencyOutputSupported();
    }

    private boolean isProAudioSupported() {
        return WebRtcAudioUtils.runningOnMarshmallowOrHigher() && ContextUtils.getApplicationContext().getPackageManager().hasSystemFeature("android.hardware.audio.pro");
    }

    private boolean isAAudioSupported() {
        Logging.w(TAG, "AAudio support is currently disabled on all devices!");
        return false;
    }

    private int getNativeOutputSampleRate() {
        int sampleRateHz;
        if (WebRtcAudioUtils.runningOnEmulator()) {
            Logging.d(TAG, "Running emulator, overriding sample rate to 8 kHz.");
            return 8000;
        }
        if (WebRtcAudioUtils.isDefaultSampleRateOverridden()) {
            Logging.d(TAG, "Default sample rate is overriden to " + WebRtcAudioUtils.getDefaultSampleRateHz() + " Hz");
            return WebRtcAudioUtils.getDefaultSampleRateHz();
        }
        if (WebRtcAudioUtils.runningOnJellyBeanMR1OrHigher()) {
            sampleRateHz = getSampleRateOnJellyBeanMR10OrHigher();
        } else {
            sampleRateHz = WebRtcAudioUtils.getDefaultSampleRateHz();
        }
        Logging.d(TAG, "Sample rate is set to " + sampleRateHz + " Hz");
        return sampleRateHz;
    }

    private int getSampleRateOnJellyBeanMR10OrHigher() {
        String sampleRateString = this.audioManager.getProperty("android.media.property.OUTPUT_SAMPLE_RATE");
        if (this.configHelper.getAndroidRoomsConfig().isRooms()) {
            int sampleRate = McsHWDeviceHelper.getInstance().audioSampleRate();
            if (sampleRate != 48000) {
                sampleRateString = "" + sampleRate;
            }
            Logging.d(TAG, "rooms sample rate:" + sampleRateString);
        }
        return sampleRateString == null ? WebRtcAudioUtils.getDefaultSampleRateHz() : Integer.parseInt(sampleRateString);
    }

    private int getLowLatencyOutputFramesPerBuffer() {
        String framesPerBuffer;
        assertTrue(isLowLatencyOutputSupported());
        if (WebRtcAudioUtils.runningOnJellyBeanMR1OrHigher() && (framesPerBuffer = this.audioManager.getProperty("android.media.property.OUTPUT_FRAMES_PER_BUFFER")) != null) {
            return Integer.parseInt(framesPerBuffer);
        }
        return 256;
    }

    private boolean hasAudioRecordPermission() {
        return AudioHelper.hasAudioRecordPermission(ContextUtils.getApplicationContext());
    }

    private static boolean isAcousticEchoCancelerSupported() {
        return WebRtcAudioEffects.canUseAcousticEchoCanceler();
    }

    private static boolean isNoiseSuppressorSupported() {
        return WebRtcAudioEffects.canUseNoiseSuppressor();
    }

    private static int getMinOutputFrameSize(int sampleRateInHz, int numChannels) {
        int bytesPerFrame = numChannels * 2;
        int channelConfig = numChannels == 1 ? 4 : 12;
        return AudioTrack.getMinBufferSize(sampleRateInHz, channelConfig, 2) / bytesPerFrame;
    }

    private int getLowLatencyInputFramesPerBuffer() {
        assertTrue(isLowLatencyInputSupported());
        return getLowLatencyOutputFramesPerBuffer();
    }

    private static int getMinInputFrameSize(int sampleRateInHz, int numChannels) {
        int bytesPerFrame = numChannels * 2;
        int channelConfig = numChannels == 1 ? 16 : 12;
        return AudioRecord.getMinBufferSize(sampleRateInHz, channelConfig, 2) / bytesPerFrame;
    }

    private static void assertTrue(boolean condition) {
        if (!condition) {
            throw new AssertionError("Expected condition to be true");
        }
    }
}
