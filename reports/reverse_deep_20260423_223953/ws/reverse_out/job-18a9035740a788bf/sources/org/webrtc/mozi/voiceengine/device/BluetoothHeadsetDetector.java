package org.webrtc.mozi.voiceengine.device;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.StringUtils;
import org.webrtc.mozi.utils.ThreadExecutor;

/* JADX INFO: loaded from: classes3.dex */
public class BluetoothHeadsetDetector extends BaseBluetoothDetector {
    private static final long REFRESH_CONNECTION_DELAY = 500;
    private static final long SOC_DISCONNECTED_DELAY = 300;
    private static final String TAG = "[ble] BluetoothHeadsetDetectorV2";
    private boolean mBluetoothHeadsetConnected;
    private final BluetoothHeadsetDevice mBluetoothHeadsetDevice;
    private BluetoothStateListener mBluetoothStateListener;
    private final Context mContext;
    private final boolean mOptimizeBluetoothSco;
    private final Runnable mRefreshRunnable;
    private final Runnable mScoStateRunnable;

    public BluetoothHeadsetDetector(Context context, boolean optimizeBluetoothSco, boolean enableReConnectBluetoothSco) {
        super(AudioRouteType.Bluetooth);
        this.mRefreshRunnable = new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothHeadsetDetector.1
            @Override // java.lang.Runnable
            public void run() {
                BluetoothHeadsetDetector.this.refreshBluetoothHeadsetConnection();
            }
        };
        this.mScoStateRunnable = new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothHeadsetDetector.2
            @Override // java.lang.Runnable
            public void run() {
                BluetoothHeadsetDetector.this.refreshScoAudioConnection();
            }
        };
        this.mContext = context;
        this.mOptimizeBluetoothSco = optimizeBluetoothSco;
        this.mBluetoothHeadsetDevice = new BluetoothHeadsetDevice(context, enableReConnectBluetoothSco);
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector
    public void startDetect() {
        if (this.mBluetoothStateListener == null) {
            this.mBluetoothStateListener = new BluetoothStateListener();
        }
        IntentFilter filter = new IntentFilter();
        filter.addAction("android.bluetooth.adapter.action.STATE_CHANGED");
        filter.addAction("android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED");
        filter.addAction("android.bluetooth.headset.profile.action.AUDIO_STATE_CHANGED");
        filter.addAction("android.media.ACTION_SCO_AUDIO_STATE_UPDATED");
        this.mContext.registerReceiver(this.mBluetoothStateListener, filter);
        try {
            this.mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
            if (this.mBluetoothAdapter != null) {
                this.mBluetoothAdapter.getProfileProxy(this.mContext, new BluetoothProfile.ServiceListener() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothHeadsetDetector.3
                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceConnected(int profile, BluetoothProfile proxy) {
                        Logging.i(BluetoothHeadsetDetector.TAG, "BluetoothProfile.HEADSET onServiceConnected");
                        if (proxy instanceof BluetoothHeadset) {
                            BluetoothHeadsetDetector.this.mBluetoothHeadset = (BluetoothHeadset) proxy;
                            BluetoothHeadsetDetector.this.refreshBluetoothHeadsetConnection();
                        }
                    }

                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceDisconnected(int profile) {
                        Logging.i(BluetoothHeadsetDetector.TAG, "BluetoothProfile.HEADSET onServiceDisconnected");
                    }
                }, 1);
            }
        } catch (Throwable e) {
            Logging.i(TAG, "getProfileProxy error: " + e.getMessage());
        }
        refreshBluetoothHeadsetConnection();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void refreshScoAudioConnection() {
        boolean scoAudioActive = this.mBluetoothHeadsetDevice.isScoAudioConnected();
        Logging.i(TAG, "refreshScoAudioConnection connected: " + scoAudioActive);
        if (scoAudioActive) {
            this.mBluetoothHeadsetDevice.handleScoAudioConnected();
        } else if (this.mBluetoothHeadsetDevice.isScoAudioDisconnected()) {
            this.mBluetoothHeadsetDevice.handleScoAudioDisconnected();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void refreshBluetoothHeadsetConnection() {
        boolean isBluetoothHeadsetConnected = this.mBluetoothHeadsetDevice.checkBluetoothScoConnection(this.mBluetoothHeadset);
        Logging.i(TAG, "refreshBluetoothHeadsetConnection connected: " + isBluetoothHeadsetConnected + ", before = " + this.mBluetoothHeadsetConnected);
        if (this.mBluetoothHeadsetConnected != isBluetoothHeadsetConnected) {
            this.mBluetoothHeadsetConnected = isBluetoothHeadsetConnected;
            if (isBluetoothHeadsetConnected) {
                onDeviceAvailable(this.mBluetoothHeadsetDevice);
            } else {
                onDeviceUnavailable(this.mBluetoothHeadsetDevice);
            }
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.BaseBluetoothDetector
    public boolean isBluetoothOn() {
        return this.mBluetoothHeadsetDevice.isBluetoothOn();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void refreshBluetoothHeadsetConnectionDelay() {
        Logging.i(TAG, "refreshBluetoothHeadsetConnectionDelay");
        ThreadExecutor.getMainHandler().removeCallbacks(this.mRefreshRunnable);
        ThreadExecutor.getMainHandler().postDelayed(this.mRefreshRunnable, 500L);
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector
    public void stopDetect() {
        BluetoothStateListener bluetoothStateListener = this.mBluetoothStateListener;
        if (bluetoothStateListener != null) {
            this.mContext.unregisterReceiver(bluetoothStateListener);
        }
        try {
            if (this.mBluetoothAdapter != null && this.mBluetoothHeadset != null) {
                this.mBluetoothAdapter.closeProfileProxy(1, this.mBluetoothHeadset);
                this.mBluetoothHeadset = null;
                refreshBluetoothHeadsetConnection();
            }
        } catch (Exception e) {
            Logging.w(TAG, "Bluetooth has exp, " + e.getMessage());
        }
    }

    private class BluetoothStateListener extends BroadcastReceiver {
        private BluetoothStateListener() {
        }

        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if (intent == null || intent.getAction() == null) {
                return;
            }
            String action = intent.getAction();
            byte b = -1;
            switch (action.hashCode()) {
                case -1692127708:
                    if (action.equals("android.media.ACTION_SCO_AUDIO_STATE_UPDATED")) {
                        b = 3;
                    }
                    break;
                case -1530327060:
                    if (action.equals("android.bluetooth.adapter.action.STATE_CHANGED")) {
                        b = 0;
                    }
                    break;
                case -1435586571:
                    if (action.equals("android.bluetooth.headset.profile.action.AUDIO_STATE_CHANGED")) {
                        b = 2;
                    }
                    break;
                case 545516589:
                    if (action.equals("android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED")) {
                        b = 1;
                    }
                    break;
            }
            if (b == 0) {
                int preState = intent.getIntExtra("android.bluetooth.adapter.extra.PREVIOUS_STATE", 10);
                int state = intent.getIntExtra("android.bluetooth.adapter.extra.STATE", 10);
                Logging.i(BluetoothHeadsetDetector.TAG, StringUtils.getAppendString("BluetoothAdapter.ACTION_STATE_CHANGED: ", BluetoothHeadsetDetector.this.adapterStateToString(preState), "=>", BluetoothHeadsetDetector.this.adapterStateToString(state)));
                BluetoothHeadsetDetector.this.mBluetoothHeadsetDevice.setBluetoothState(state);
                BluetoothHeadsetDetector.this.refreshBluetoothHeadsetConnectionDelay();
                return;
            }
            if (b == 1) {
                int preState2 = intent.getIntExtra("android.bluetooth.profile.extra.PREVIOUS_STATE", 0);
                Logging.i(BluetoothHeadsetDetector.TAG, StringUtils.getAppendString("BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED: ", BluetoothHeadsetDetector.this.profileStateToString(preState2), "=>", BluetoothHeadsetDetector.this.profileStateToString(intent.getIntExtra("android.bluetooth.profile.extra.STATE", 0)), ", device=", BluetoothHeadsetDetector.this.getDeviceName(intent.getExtras())));
                BluetoothHeadsetDetector.this.refreshBluetoothHeadsetConnectionDelay();
                BluetoothHeadsetDetector bluetoothHeadsetDetector = BluetoothHeadsetDetector.this;
                bluetoothHeadsetDetector.logBluetoothHeadsetInfo(bluetoothHeadsetDetector.mBluetoothHeadset);
                return;
            }
            if (b == 2) {
                int preState3 = intent.getIntExtra("android.bluetooth.profile.extra.PREVIOUS_STATE", 10);
                Logging.i(BluetoothHeadsetDetector.TAG, StringUtils.getAppendString("BluetoothHeadset.ACTION_AUDIO_STATE_CHANGED: ", BluetoothHeadsetDetector.this.headsetScoStateToString(preState3), "=>", BluetoothHeadsetDetector.this.headsetScoStateToString(intent.getIntExtra("android.bluetooth.profile.extra.STATE", 10)), ", device=", BluetoothHeadsetDetector.this.getDeviceName(intent.getExtras())));
                BluetoothHeadsetDetector.this.refreshBluetoothHeadsetConnectionDelay();
                BluetoothHeadsetDetector bluetoothHeadsetDetector2 = BluetoothHeadsetDetector.this;
                bluetoothHeadsetDetector2.logBluetoothHeadsetInfo(bluetoothHeadsetDetector2.mBluetoothHeadset);
                return;
            }
            if (b == 3) {
                int preState4 = intent.getIntExtra("android.media.extra.SCO_AUDIO_PREVIOUS_STATE", 0);
                int state2 = intent.getIntExtra("android.media.extra.SCO_AUDIO_STATE", 0);
                Logging.i(BluetoothHeadsetDetector.TAG, StringUtils.getAppendString("AudioManager.ACTION_SCO_AUDIO_STATE_UPDATED: ", BluetoothHeadsetDetector.this.audioManagerStateToString(preState4), "=>", BluetoothHeadsetDetector.this.audioManagerStateToString(state2)));
                BluetoothHeadsetDetector.this.mBluetoothHeadsetDevice.setAudioState(state2);
                if (BluetoothHeadsetDetector.this.mOptimizeBluetoothSco) {
                    if (state2 == 0) {
                        ThreadExecutor.getMainHandler().removeCallbacks(BluetoothHeadsetDetector.this.mScoStateRunnable);
                        ThreadExecutor.getMainHandler().postDelayed(BluetoothHeadsetDetector.this.mScoStateRunnable, BluetoothHeadsetDetector.SOC_DISCONNECTED_DELAY);
                    }
                    if (state2 == 1) {
                        ThreadExecutor.getMainHandler().removeCallbacks(BluetoothHeadsetDetector.this.mScoStateRunnable);
                        BluetoothHeadsetDetector.this.mScoStateRunnable.run();
                        return;
                    }
                    return;
                }
                if (state2 == 1 || state2 == 0) {
                    BluetoothHeadsetDetector.this.refreshScoAudioConnection();
                }
            }
        }
    }
}
