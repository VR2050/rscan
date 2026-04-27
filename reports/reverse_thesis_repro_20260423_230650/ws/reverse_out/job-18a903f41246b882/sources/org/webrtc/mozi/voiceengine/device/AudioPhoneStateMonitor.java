package org.webrtc.mozi.voiceengine.device;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;
import java.util.List;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.voiceengine.device.AudioHelper;

/* JADX INFO: loaded from: classes3.dex */
public class AudioPhoneStateMonitor {
    private static final String TAG = "AudioPhoneStateMonitor";
    private PhoneStateListener mPhoneStateListener = null;
    private Handler mHandler = null;
    private Context mContext = null;
    private AudioPhoneStateListener mListener = null;
    private Object mEventLock = new Object();
    private boolean mInitialize = false;
    private boolean mIsInterrupted = false;

    public interface AudioPhoneStateListener {
        void onAudioInterrupted(boolean z);
    }

    public void onPhoneStateChanged(int state) {
        try {
            Logging.d(TAG, "onPhoneStateChanged, state: " + AudioHelper.phoneStateToString(state));
            if (state == 0) {
                synchronized (this.mEventLock) {
                    if (this.mIsInterrupted) {
                        this.mIsInterrupted = false;
                        if (this.mListener != null) {
                            this.mListener.onAudioInterrupted(false);
                        }
                    }
                }
            } else if (state == 1) {
                synchronized (this.mEventLock) {
                    if (!this.mIsInterrupted) {
                        this.mIsInterrupted = true;
                        if (this.mListener != null) {
                            this.mListener.onAudioInterrupted(true);
                        }
                    }
                }
            } else if (state == 2) {
                synchronized (this.mEventLock) {
                    if (!this.mIsInterrupted) {
                        this.mIsInterrupted = true;
                        if (this.mListener != null) {
                            this.mListener.onAudioInterrupted(true);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Logging.e(TAG, "onPhoneStateChanged failed, error: " + e.getMessage());
        }
    }

    public void setListener(AudioPhoneStateListener listener) {
        synchronized (this.mEventLock) {
            this.mListener = listener;
        }
    }

    public void init(Context context) {
        if (this.mInitialize) {
            return;
        }
        this.mContext = context;
        this.mHandler = new Handler(Looper.getMainLooper());
        this.mInitialize = true;
    }

    public void destroy() {
        if (!this.mInitialize) {
            return;
        }
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
            this.mHandler = null;
        }
        if (this.mContext != null) {
            this.mContext = null;
        }
        this.mInitialize = false;
    }

    private void printRecordingInfo() {
        try {
            List<AudioHelper.RecordAppInfo> recordingAppInfo = AudioHelper.getRecordingAppInfo(this.mContext);
            Logging.i(TAG, "init recordingAppInfo: " + recordingAppInfo);
        } catch (Exception e) {
            Logging.e(TAG, "get init recordingAppInfo failed, error: " + e.getMessage());
        }
    }

    private boolean hasPermission() {
        try {
            boolean permission = AudioHelper.hasPhoneStatePermission(this.mContext);
            Logging.i(TAG, "READ_PHONE_STATE permission: " + permission);
            return permission;
        } catch (Exception e) {
            Logging.e(TAG, "check READ_PHONE_STATE permission failed, error: " + e.getMessage());
            return false;
        }
    }

    public void startMonitor() {
        Handler handler;
        Logging.d(TAG, "startMonitor");
        if (!this.mInitialize) {
            return;
        }
        printRecordingInfo();
        if (hasPermission() && (handler = this.mHandler) != null) {
            handler.post(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioPhoneStateMonitor.1
                @Override // java.lang.Runnable
                public void run() {
                    AudioPhoneStateMonitor.this.mPhoneStateListener = new PhoneStateListener() { // from class: org.webrtc.mozi.voiceengine.device.AudioPhoneStateMonitor.1.1
                        @Override // android.telephony.PhoneStateListener
                        public void onCallStateChanged(int state, String incomingNumber) {
                            AudioPhoneStateMonitor.this.onPhoneStateChanged(state);
                        }
                    };
                    try {
                        TelephonyManager telephonyManager = (TelephonyManager) AudioPhoneStateMonitor.this.mContext.getSystemService("phone");
                        int callState = telephonyManager.getCallState();
                        Logging.i(AudioPhoneStateMonitor.TAG, "init call state: " + callState);
                        AudioPhoneStateMonitor.this.onPhoneStateChanged(callState);
                        telephonyManager.listen(AudioPhoneStateMonitor.this.mPhoneStateListener, 32);
                    } catch (Exception e) {
                        Logging.e(AudioPhoneStateMonitor.TAG, "TelephonyManager listen call state error: " + e.getMessage());
                        AudioPhoneStateMonitor.this.mPhoneStateListener = null;
                    }
                }
            });
        }
    }

    public void stopMonitor() {
        Handler handler;
        Logging.i(TAG, "stopMonitor");
        if (this.mInitialize && (handler = this.mHandler) != null) {
            handler.post(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioPhoneStateMonitor.2
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        if (AudioPhoneStateMonitor.this.mPhoneStateListener != null) {
                            Logging.i(AudioPhoneStateMonitor.TAG, "stop call state listen");
                            TelephonyManager telephonyManager = (TelephonyManager) AudioPhoneStateMonitor.this.mContext.getSystemService("phone");
                            telephonyManager.listen(AudioPhoneStateMonitor.this.mPhoneStateListener, 0);
                            AudioPhoneStateMonitor.this.mPhoneStateListener = null;
                        }
                    } catch (Exception e) {
                        Logging.e(AudioPhoneStateMonitor.TAG, "stopMonitor failed, error:  " + e.getMessage());
                    }
                }
            });
        }
    }
}
