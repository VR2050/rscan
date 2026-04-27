package org.webrtc.mozi.voiceengine.device;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.StringUtils;

/* JADX INFO: loaded from: classes3.dex */
public class BluetoothA2dpDetector extends BaseBluetoothDetector {
    private static final String TAG = "[ble] BluetoothA2dpDetector";
    private BluetoothA2dp mBluetoothA2dp;
    private boolean mBluetoothA2dpConnected;
    private BluetoothStateListener mBluetoothStateListener;
    private Context mContext;
    private BluetoothA2dpDevice mDevice;

    public BluetoothA2dpDetector(Context context) {
        super(AudioRouteType.A2dp);
        this.mContext = context;
        this.mDevice = new BluetoothA2dpDevice(context);
        try {
            BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
            if (bluetoothAdapter != null) {
                bluetoothAdapter.getProfileProxy(this.mContext, new BluetoothProfile.ServiceListener() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothA2dpDetector.1
                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceConnected(int profile, BluetoothProfile proxy) {
                        Logging.i(BluetoothA2dpDetector.TAG, "BluetoothProfile.A2DP onServiceConnected");
                        if (proxy instanceof BluetoothA2dp) {
                            BluetoothA2dpDetector.this.mBluetoothA2dp = (BluetoothA2dp) proxy;
                            BluetoothA2dpDetector.this.refreshBluetoothA2dpConnection();
                        }
                    }

                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceDisconnected(int profile) {
                        Logging.i(BluetoothA2dpDetector.TAG, "BluetoothProfile.A2DP onServiceDisconnected");
                    }
                }, 2);
                bluetoothAdapter.getProfileProxy(this.mContext, new BluetoothProfile.ServiceListener() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothA2dpDetector.2
                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceConnected(int profile, BluetoothProfile proxy) {
                        Logging.i(BluetoothA2dpDetector.TAG, "BluetoothProfile.HEADSET onServiceConnected");
                        if (proxy instanceof BluetoothHeadset) {
                            BluetoothA2dpDetector.this.mBluetoothHeadset = (BluetoothHeadset) proxy;
                            BluetoothA2dpDetector.this.refreshBluetoothA2dpConnection();
                        }
                    }

                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceDisconnected(int profile) {
                        Logging.i(BluetoothA2dpDetector.TAG, "BluetoothProfile.HEADSET onServiceDisconnected");
                    }
                }, 1);
            }
        } catch (Throwable e) {
            Logging.i(TAG, "getProfileProxy error: " + e.getMessage());
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector
    public void startDetect() {
        if (this.mBluetoothStateListener == null) {
            this.mBluetoothStateListener = new BluetoothStateListener();
        }
        IntentFilter filter = new IntentFilter();
        filter.addAction("android.bluetooth.adapter.action.STATE_CHANGED");
        filter.addAction("android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED");
        filter.addAction("android.bluetooth.a2dp.profile.action.CONNECTION_STATE_CHANGED");
        filter.addAction("android.bluetooth.a2dp.profile.action.PLAYING_STATE_CHANGED");
        this.mContext.registerReceiver(this.mBluetoothStateListener, filter);
        refreshBluetoothA2dpConnection();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void refreshBluetoothA2dpConnection() {
        boolean isBluetoothA2dpConnected = this.mDevice.checkBluetoothA2dpConnection(this.mBluetoothA2dp, this.mBluetoothHeadset);
        Logging.i(TAG, "refreshBluetoothA2dpConnection connected: " + isBluetoothA2dpConnected + ", before = " + this.mBluetoothA2dpConnected);
        if (this.mBluetoothA2dpConnected != isBluetoothA2dpConnected) {
            this.mBluetoothA2dpConnected = isBluetoothA2dpConnected;
            if (isBluetoothA2dpConnected) {
                onDeviceAvailable(this.mDevice);
            } else {
                onDeviceUnavailable(this.mDevice);
            }
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector
    public void stopDetect() {
        BluetoothStateListener bluetoothStateListener = this.mBluetoothStateListener;
        if (bluetoothStateListener != null) {
            this.mContext.unregisterReceiver(bluetoothStateListener);
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.BaseBluetoothDetector
    protected boolean isBluetoothOn() {
        return this.mDevice.isBluetoothOn();
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
                case -1530327060:
                    if (action.equals("android.bluetooth.adapter.action.STATE_CHANGED")) {
                        b = 0;
                    }
                    break;
                case -855499628:
                    if (action.equals("android.bluetooth.a2dp.profile.action.PLAYING_STATE_CHANGED")) {
                        b = 3;
                    }
                    break;
                case 545516589:
                    if (action.equals("android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED")) {
                        b = 1;
                    }
                    break;
                case 1244161670:
                    if (action.equals("android.bluetooth.a2dp.profile.action.CONNECTION_STATE_CHANGED")) {
                        b = 2;
                    }
                    break;
            }
            if (b == 0) {
                int state = intent.getIntExtra("android.bluetooth.adapter.extra.STATE", 10);
                BluetoothA2dpDetector.this.mDevice.setBluetoothState(state);
                BluetoothA2dpDetector.this.refreshBluetoothA2dpConnection();
                return;
            }
            if (b == 1) {
                BluetoothA2dpDetector.this.refreshBluetoothA2dpConnection();
                BluetoothA2dpDetector bluetoothA2dpDetector = BluetoothA2dpDetector.this;
                bluetoothA2dpDetector.logBluetoothA2dpInfo(bluetoothA2dpDetector.mBluetoothA2dp);
                return;
            }
            if (b == 2) {
                int preState = intent.getIntExtra("android.bluetooth.profile.extra.PREVIOUS_STATE", 0);
                int state2 = intent.getIntExtra("android.bluetooth.profile.extra.STATE", 0);
                Logging.i(BluetoothA2dpDetector.TAG, StringUtils.getAppendString("BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED: ", BluetoothA2dpDetector.this.profileStateToString(preState), "=>", BluetoothA2dpDetector.this.profileStateToString(state2), ", device=", BluetoothA2dpDetector.this.getDeviceName(intent.getExtras())));
                BluetoothA2dpDetector.this.refreshBluetoothA2dpConnection();
                BluetoothA2dpDetector bluetoothA2dpDetector2 = BluetoothA2dpDetector.this;
                bluetoothA2dpDetector2.logBluetoothA2dpInfo(bluetoothA2dpDetector2.mBluetoothA2dp);
                return;
            }
            if (b == 3) {
                int preState2 = intent.getIntExtra("android.bluetooth.profile.extra.PREVIOUS_STATE", 11);
                int state3 = intent.getIntExtra("android.bluetooth.profile.extra.STATE", 11);
                Logging.i(BluetoothA2dpDetector.TAG, StringUtils.getAppendString("BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED: ", BluetoothA2dpDetector.this.a2dpStateToString(preState2), "=>", BluetoothA2dpDetector.this.a2dpStateToString(state3), ", device=", BluetoothA2dpDetector.this.getDeviceName(intent.getExtras())));
                BluetoothA2dpDetector.this.refreshBluetoothA2dpConnection();
                BluetoothA2dpDetector bluetoothA2dpDetector3 = BluetoothA2dpDetector.this;
                bluetoothA2dpDetector3.logBluetoothA2dpInfo(bluetoothA2dpDetector3.mBluetoothA2dp);
            }
        }
    }
}
