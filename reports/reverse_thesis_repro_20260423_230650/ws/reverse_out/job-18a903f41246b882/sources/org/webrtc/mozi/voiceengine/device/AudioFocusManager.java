package org.webrtc.mozi.voiceengine.device;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.os.Build;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public class AudioFocusManager {
    private static final String TAG = "AudioFocusManager";
    private AudioFocusRequest mAudioFocusRequest;
    private AudioManager mAudioManager;
    private Object mEventLock;
    private AudioManager.OnAudioFocusChangeListener mFocusListener;
    private AudioFocusChangeListener mListener;

    public interface AudioFocusChangeListener {
        void onAudioFocusChanged(int i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onAudioFocusChanged(int focusChange) {
        try {
            Logging.i(TAG, "onAudioFocusChanged: " + AudioHelper.audioFocusToString(focusChange));
            synchronized (this.mEventLock) {
                if (this.mListener != null) {
                    this.mListener.onAudioFocusChanged(focusChange);
                }
            }
        } catch (Exception e) {
            Logging.e(TAG, "onAudioFocusChanged failed, error: " + e.getMessage());
        }
    }

    public static AudioFocusManager getInstance(Context context) {
        SingleInstanceHolder.INSTANCE.init(context);
        return SingleInstanceHolder.INSTANCE;
    }

    private AudioFocusManager() {
        this.mFocusListener = new AudioManager.OnAudioFocusChangeListener() { // from class: org.webrtc.mozi.voiceengine.device.AudioFocusManager.1
            @Override // android.media.AudioManager.OnAudioFocusChangeListener
            public void onAudioFocusChange(int focusChange) {
                AudioFocusManager.this.onAudioFocusChanged(focusChange);
            }
        };
        this.mEventLock = new Object();
    }

    private void init(Context context) {
        if (this.mAudioManager == null && context != null) {
            this.mAudioManager = (AudioManager) context.getSystemService("audio");
        }
    }

    private static final class SingleInstanceHolder {
        private static final AudioFocusManager INSTANCE = new AudioFocusManager();

        private SingleInstanceHolder() {
        }
    }

    public void setListener(AudioFocusChangeListener listener) {
        synchronized (this.mEventLock) {
            this.mListener = listener;
        }
    }

    public void requireFocus() {
        if (Build.VERSION.SDK_INT < 26) {
            requireFocusLegacy();
        } else {
            requireFocusNew();
        }
    }

    private void requireFocusLegacy() {
        AudioManager audioManager = this.mAudioManager;
        if (audioManager != null) {
            int requestAudioFocus = audioManager.requestAudioFocus(this.mFocusListener, 0, 1);
            Logging.i(TAG, "requestAudioFocus: " + AudioHelper.audioFocusToString(requestAudioFocus));
        }
    }

    private void requireFocusNew() {
        AudioFocusRequest audioFocusRequestBuild = new AudioFocusRequest.Builder(2).setOnAudioFocusChangeListener(this.mFocusListener).setAudioAttributes(new AudioAttributes.Builder().setUsage(2).setContentType(1).build()).build();
        this.mAudioFocusRequest = audioFocusRequestBuild;
        AudioManager audioManager = this.mAudioManager;
        if (audioManager != null) {
            int requestAudioFocus = audioManager.requestAudioFocus(audioFocusRequestBuild);
            Logging.i(TAG, "requestAudioFocus: " + AudioHelper.audioFocusToString(requestAudioFocus));
        }
    }

    public void releaseFocus() {
        if (Build.VERSION.SDK_INT < 26) {
            releaseFocusLegacy();
        } else {
            releaseFocusNew();
        }
    }

    private void releaseFocusLegacy() {
        AudioManager audioManager = this.mAudioManager;
        if (audioManager != null) {
            audioManager.abandonAudioFocus(this.mFocusListener);
        }
    }

    private void releaseFocusNew() {
        AudioManager audioManager;
        AudioFocusRequest audioFocusRequest = this.mAudioFocusRequest;
        if (audioFocusRequest != null && (audioManager = this.mAudioManager) != null) {
            try {
                audioManager.abandonAudioFocusRequest(audioFocusRequest);
            } catch (Throwable e) {
                Logging.e(TAG, "abandon audio focus exception, " + e.getMessage());
            }
            this.mAudioFocusRequest = null;
        }
    }
}
