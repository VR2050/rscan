package org.webrtc.mozi.voiceengine.device;

import android.app.Application;
import android.content.Context;
import android.media.AudioManager;
import android.os.Build;
import org.webrtc.mozi.ContextUtils;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.StringUtils;
import org.webrtc.mozi.utils.ThreadExecutor;
import org.webrtc.mozi.voiceengine.WebRtcAudioManager;
import org.webrtc.mozi.voiceengine.device.AudioAppBackgroundMonitor;
import org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher;
import org.webrtc.mozi.voiceengine.device.AudioFocusManager;
import org.webrtc.mozi.voiceengine.device.AudioPhoneStateMonitor;

/* JADX INFO: loaded from: classes3.dex */
public class AudioDeviceManager implements AudioPhoneStateMonitor.AudioPhoneStateListener, AudioFocusManager.AudioFocusChangeListener, AudioAppBackgroundMonitor.AudioAppBackgroundListener {
    private static final String BRAND_MEIZU = "Meizu";
    private static final long CHECK_AUDIO_DEVICE_STATE_DELAY = 500;
    private static final String DEVICE_MEIZU_PRO7S = "PRO7S";
    private static final String TAG = "AudioDeviceManager";
    private AudioAppBackgroundMonitor mAudioAppBackgroundMonitor;
    private AbstractAudioDevice mAudioDevice;
    private AudioManager mAudioManager;
    private AudioDeviceListener mAudioModeListener;
    private AudioPhoneStateMonitor mAudioPhoneStateMonitor;
    private AudioVolumeMonitor mAudioVolumeMonitor;
    private AudioDeviceSwitcher.AutoSwitchReference mAutoSwitchReference;
    private final Runnable mCheckRunnable;
    private AudioRouteType mDefaultAudioRouteType;
    private boolean mDefaultToSpeakerphone;
    private boolean mEnableGeneralAudioOpt;
    private Object mEventLock;
    private boolean mIsAudioFocusLost;
    private boolean mIsAudioInterrupted;
    private boolean mIsOnBackground;
    private AudioDeviceManagerListener mListener;
    private int mSaveAudioMode;

    public interface AudioDeviceManagerListener {
        void onAudioFocusChanged(int i);

        void onAudioInterrupted(boolean z);

        void onAudioRouteChanged(AudioRouteType audioRouteType);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkAndReactivateAudioDevice() {
        try {
            AbstractAudioDevice audioDevice = AudioDeviceSwitcher.getInstance().getActiveDevice();
            if (audioDevice != null) {
                audioDevice.checkAndReactivate();
            }
            Logging.i(TAG, "checkAndReactivateAudioDevice, before interrupted audio device: " + this.mAudioDevice + ", current audio device: " + audioDevice + ", interrupted: " + this.mIsAudioInterrupted);
            if (this.mAudioDevice != null && this.mAudioDevice != audioDevice && !this.mIsAudioInterrupted) {
                AudioDeviceSwitcher.getInstance().activate(this.mAudioDevice.getAudioRouteType());
                this.mAudioDevice = null;
            }
        } catch (Exception e) {
            Logging.e(TAG, "checkAndReactivateAudioDevice, error: " + e.getMessage());
        }
    }

    private void saveAudioDevice() {
        try {
            this.mAudioDevice = AudioDeviceSwitcher.getInstance().getActiveDevice();
            Logging.i(TAG, "saveAudioDevice audio device: " + this.mAudioDevice);
        } catch (Exception e) {
            Logging.e(TAG, "saveAudioDevice error: " + e.getMessage());
        }
    }

    private void checkAndReactivateAudioDeviceDelay() {
        Logging.i(TAG, "checkAndReactivateAudioDeviceDelay");
        ThreadExecutor.getMainHandler().removeCallbacks(this.mCheckRunnable);
        ThreadExecutor.getMainHandler().postDelayed(this.mCheckRunnable, 500L);
    }

    @Override // org.webrtc.mozi.voiceengine.device.AudioAppBackgroundMonitor.AudioAppBackgroundListener
    public void onEnterForeground() {
        Logging.i(TAG, "onEnterForeground");
        printAudioManagerStates();
        if (this.mIsOnBackground) {
            checkAndReactivateAudioDeviceDelay();
        }
        this.mIsOnBackground = false;
    }

    @Override // org.webrtc.mozi.voiceengine.device.AudioAppBackgroundMonitor.AudioAppBackgroundListener
    public void onEnterBackground() {
        Logging.i(TAG, "onEnterBackground");
        this.mIsOnBackground = true;
        printAudioManagerStates();
    }

    @Override // org.webrtc.mozi.voiceengine.device.AudioFocusManager.AudioFocusChangeListener
    public void onAudioFocusChanged(int focusChanged) {
        Logging.i(TAG, "onAudioFocusChanged, focusChanged: " + AudioHelper.audioFocusToString(focusChanged));
        printAudioManagerStates();
        if (focusChanged == -3 || focusChanged == -2 || focusChanged == -1) {
            this.mIsAudioFocusLost = true;
        } else if (focusChanged == 1 || focusChanged == 2 || focusChanged == 3 || focusChanged == 4) {
            if (this.mIsAudioFocusLost) {
                checkAndReactivateAudioDeviceDelay();
            }
            this.mIsAudioFocusLost = false;
        }
        synchronized (this.mEventLock) {
            if (this.mListener != null) {
                this.mListener.onAudioFocusChanged(focusChanged);
            }
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AudioPhoneStateMonitor.AudioPhoneStateListener
    public void onAudioInterrupted(boolean interrupted) {
        Logging.i(TAG, "onAudioInterrupted, interrupted: " + interrupted);
        this.mIsAudioInterrupted = interrupted;
        printAudioManagerStates();
        if (interrupted) {
            saveAudioDevice();
        }
        if (!interrupted) {
            checkAndReactivateAudioDeviceDelay();
        }
        synchronized (this.mEventLock) {
            if (this.mListener != null) {
                this.mListener.onAudioInterrupted(interrupted);
            }
        }
    }

    public AudioDeviceManager() {
        this.mDefaultAudioRouteType = AudioRouteType.Speakerphone;
        this.mSaveAudioMode = -2;
        this.mEnableGeneralAudioOpt = false;
        this.mEventLock = new Object();
        this.mCheckRunnable = new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceManager.1
            @Override // java.lang.Runnable
            public void run() {
                AudioDeviceManager.this.checkAndReactivateAudioDevice();
            }
        };
        this.mAudioModeListener = new AudioDeviceListener() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceManager.2
            @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceListener
            public void onAudioDeviceChange(final AbstractAudioDevice device) {
                Logging.i(AudioDeviceManager.TAG, "onAudioDeviceChange device name: " + device.getName() + ", audioRouteType: " + device.getAudioRouteType());
                if (AudioDeviceManager.this.mEnableGeneralAudioOpt && WebRtcAudioManager.sMode == 0) {
                    Logging.i(AudioDeviceManager.TAG, "onAudioDeviceChange in music mode, no need set audio mode");
                } else {
                    ThreadExecutor.execute(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceManager.2.1
                        @Override // java.lang.Runnable
                        public void run() {
                            AudioDeviceManager.this.setAudioModeWhenDeviceChange(device);
                        }
                    });
                }
                if (AudioDeviceManager.this.mListener != null) {
                    AudioDeviceManager.this.mListener.onAudioRouteChanged(device.getAudioRouteType());
                }
            }

            @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceListener
            public void onAudioDeviceAvailable(AbstractAudioDevice device) {
                Logging.i(AudioDeviceManager.TAG, "onAudioDeviceAvailable device name: " + device.getName() + ", audioRouteType: " + device.getAudioRouteType());
            }

            @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceListener
            public void onAudioDeviceUnavailable(AbstractAudioDevice device) {
                Logging.i(AudioDeviceManager.TAG, "onAudioDeviceUnavailable device name: " + device.getName() + ", audioRouteType: " + device.getAudioRouteType());
            }
        };
    }

    public AudioDeviceManager(boolean enableGeneralAudioOpt) {
        this.mDefaultAudioRouteType = AudioRouteType.Speakerphone;
        this.mSaveAudioMode = -2;
        this.mEnableGeneralAudioOpt = false;
        this.mEventLock = new Object();
        this.mCheckRunnable = new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceManager.1
            @Override // java.lang.Runnable
            public void run() {
                AudioDeviceManager.this.checkAndReactivateAudioDevice();
            }
        };
        this.mAudioModeListener = new AudioDeviceListener() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceManager.2
            @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceListener
            public void onAudioDeviceChange(final AbstractAudioDevice device) {
                Logging.i(AudioDeviceManager.TAG, "onAudioDeviceChange device name: " + device.getName() + ", audioRouteType: " + device.getAudioRouteType());
                if (AudioDeviceManager.this.mEnableGeneralAudioOpt && WebRtcAudioManager.sMode == 0) {
                    Logging.i(AudioDeviceManager.TAG, "onAudioDeviceChange in music mode, no need set audio mode");
                } else {
                    ThreadExecutor.execute(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceManager.2.1
                        @Override // java.lang.Runnable
                        public void run() {
                            AudioDeviceManager.this.setAudioModeWhenDeviceChange(device);
                        }
                    });
                }
                if (AudioDeviceManager.this.mListener != null) {
                    AudioDeviceManager.this.mListener.onAudioRouteChanged(device.getAudioRouteType());
                }
            }

            @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceListener
            public void onAudioDeviceAvailable(AbstractAudioDevice device) {
                Logging.i(AudioDeviceManager.TAG, "onAudioDeviceAvailable device name: " + device.getName() + ", audioRouteType: " + device.getAudioRouteType());
            }

            @Override // org.webrtc.mozi.voiceengine.device.AudioDeviceListener
            public void onAudioDeviceUnavailable(AbstractAudioDevice device) {
                Logging.i(AudioDeviceManager.TAG, "onAudioDeviceUnavailable device name: " + device.getName() + ", audioRouteType: " + device.getAudioRouteType());
            }
        };
        this.mEnableGeneralAudioOpt = enableGeneralAudioOpt;
    }

    public void init(Context context) {
        this.mAudioManager = (AudioManager) context.getSystemService("audio");
        AudioDeviceSwitcher.getInstance().init(context, new AudioDeviceSwitcher.Config(false, false, false, this.mEnableGeneralAudioOpt));
        maybeSaveAudioMode();
        startMonitor(context);
        AudioDeviceSwitcher.getInstance().addListener(this.mAudioModeListener);
        this.mAutoSwitchReference = AudioDeviceSwitcher.getInstance().requireAutoSwitch(this.mDefaultAudioRouteType);
    }

    private void startMonitor(Context context) {
        this.mIsOnBackground = false;
        this.mIsAudioFocusLost = false;
        AudioFocusManager.getInstance(context).setListener(this);
        AudioFocusManager.getInstance(context).requireFocus();
        if (this.mAudioVolumeMonitor == null) {
            AudioVolumeMonitor audioVolumeMonitor = new AudioVolumeMonitor();
            this.mAudioVolumeMonitor = audioVolumeMonitor;
            audioVolumeMonitor.init(context);
            this.mAudioVolumeMonitor.startMonitor();
        }
        if (this.mAudioAppBackgroundMonitor == null) {
            AudioAppBackgroundMonitor audioAppBackgroundMonitor = new AudioAppBackgroundMonitor();
            this.mAudioAppBackgroundMonitor = audioAppBackgroundMonitor;
            audioAppBackgroundMonitor.init((Application) context.getApplicationContext());
            this.mAudioAppBackgroundMonitor.setListener(this);
            this.mAudioAppBackgroundMonitor.startMonitor();
        }
        if (this.mAudioPhoneStateMonitor == null) {
            AudioPhoneStateMonitor audioPhoneStateMonitor = new AudioPhoneStateMonitor();
            this.mAudioPhoneStateMonitor = audioPhoneStateMonitor;
            audioPhoneStateMonitor.init(context);
            this.mAudioPhoneStateMonitor.setListener(this);
            this.mAudioPhoneStateMonitor.startMonitor();
        }
    }

    private void stopMonitor() {
        AudioVolumeMonitor audioVolumeMonitor = this.mAudioVolumeMonitor;
        if (audioVolumeMonitor != null) {
            audioVolumeMonitor.stopMonitor();
            this.mAudioVolumeMonitor.destroy();
            this.mAudioVolumeMonitor = null;
        }
        AudioAppBackgroundMonitor audioAppBackgroundMonitor = this.mAudioAppBackgroundMonitor;
        if (audioAppBackgroundMonitor != null) {
            audioAppBackgroundMonitor.stopMonitor();
            this.mAudioAppBackgroundMonitor.setListener(null);
            this.mAudioAppBackgroundMonitor.destroy();
            this.mAudioAppBackgroundMonitor = null;
        }
        AudioPhoneStateMonitor audioPhoneStateMonitor = this.mAudioPhoneStateMonitor;
        if (audioPhoneStateMonitor != null) {
            audioPhoneStateMonitor.stopMonitor();
            this.mAudioPhoneStateMonitor.setListener(null);
            this.mAudioPhoneStateMonitor.destroy();
            this.mAudioPhoneStateMonitor = null;
        }
        AudioFocusManager.getInstance(ContextUtils.getApplicationContext()).releaseFocus();
    }

    public void destroy() {
        stopMonitor();
        AudioDeviceSwitcher.getInstance().removeListener(this.mAudioModeListener);
        AudioDeviceSwitcher.AutoSwitchReference autoSwitchReference = this.mAutoSwitchReference;
        if (autoSwitchReference != null) {
            autoSwitchReference.release();
        }
        Logging.i(TAG, "destroy with audio mode " + this.mAudioManager.getMode());
        if (this.mSaveAudioMode != -2) {
            Logging.i(TAG, "restore to audio mode " + this.mSaveAudioMode);
            AudioManagerCompat.setMode(this.mAudioManager, this.mSaveAudioMode);
        }
    }

    public void setAudioDeviceManagerListener(AudioDeviceManagerListener listener) {
        synchronized (this.mEventLock) {
            this.mListener = listener;
        }
    }

    public int setDefaultAudioRouteToSpeakerphone(boolean defaultToSpeaker) {
        AudioDeviceSwitcher.getInstance().setDefaultAudioType(defaultToSpeaker ? AudioRouteType.Speakerphone : AudioRouteType.Earpiece);
        return 0;
    }

    public int enableSpeakerphone(boolean enable) {
        if (this.mEnableGeneralAudioOpt && WebRtcAudioManager.sMode == 0 && !enable) {
            Logging.i(TAG, "enableSpeakerphone enable: " + enable + "  failed, current is in music mode");
            return -1;
        }
        AudioRouteType oldAudioRoute = AudioDeviceSwitcher.getInstance().getActiveAudioRouteType();
        Logging.i(TAG, "enableSpeakerphone enable: " + enable + ", oldAudioRoute: " + oldAudioRoute);
        if (enable) {
            AudioDeviceSwitcher.getInstance().setDefaultAudioType(AudioRouteType.Speakerphone);
            if (oldAudioRoute != AudioRouteType.Speakerphone) {
                AudioDeviceSwitcher.getInstance().activate(AudioRouteType.Speakerphone);
                return 0;
            }
            return 0;
        }
        AudioDeviceSwitcher.getInstance().setDefaultAudioType(AudioRouteType.Earpiece);
        if (oldAudioRoute == AudioRouteType.Speakerphone) {
            AudioDeviceSwitcher.getInstance().activateDefault();
            return 0;
        }
        return 0;
    }

    public boolean isSpeakerphoneEnabled() {
        return AudioDeviceSwitcher.getInstance().getActiveAudioRouteType() == AudioRouteType.Speakerphone;
    }

    private boolean isForceChangeToModeNormal(AudioRouteType audioType) {
        return audioType == AudioRouteType.WiredHeadset && StringUtils.equalsIgnoreCase(BRAND_MEIZU, Build.BRAND) && StringUtils.equalsIgnoreCase(DEVICE_MEIZU_PRO7S, Build.DEVICE);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setAudioModeWhenDeviceChange(AbstractAudioDevice device) {
        if (device != null) {
            if (isForceChangeToModeNormal(device.getAudioRouteType())) {
                Logging.i(TAG, "switch to audio mode2 0");
                AudioManagerCompat.setMode(this.mAudioManager, 0);
                return;
            }
            Logging.i(TAG, "switch to audio mode2 " + device.getPreferAudioMode());
            AudioManagerCompat.setMode(this.mAudioManager, device.getPreferAudioMode());
        }
    }

    private void maybeSaveAudioMode() {
        if (this.mSaveAudioMode == -2) {
            this.mSaveAudioMode = AudioManagerCompat.getMode(this.mAudioManager);
            Logging.i(TAG, "save audio mode " + this.mSaveAudioMode);
        }
    }

    private void printAudioManagerStates() {
        try {
            int aduioMode = this.mAudioManager.getMode();
            boolean speakerPhoneOn = this.mAudioManager.isSpeakerphoneOn();
            boolean scoOn = this.mAudioManager.isBluetoothScoOn();
            Logging.i(TAG, "current audio manager state, aduioMode: " + aduioMode + ", speakerPhoneOn: " + speakerPhoneOn + ", scoOn: " + scoOn);
        } catch (Exception e) {
            Logging.e(TAG, "printAudioManagerStates, error: " + e.getMessage());
        }
    }
}
