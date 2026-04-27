package org.webrtc.mozi.voiceengine.device;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.StringUtils;
import org.webrtc.mozi.utils.ThreadExecutor;
import org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher;

/* JADX INFO: loaded from: classes3.dex */
public class BluetoothHeadsetDetectorV3 extends BaseBluetoothDetector {
    private static final long REFRESH_CONNECTION_DELAY = 500;
    private static final String TAG = "[ble] BluetoothHeadsetDetectorV3";
    private List<BluetoothDevice> mBluetoothDeviceList;
    private List<BluetoothHeadsetDeviceV3> mBluetoothHeadsetDeviceV3List;
    private BluetoothStateListener mBluetoothStateListener;
    private final AudioDeviceSwitcher.Config mConfig;
    private Context mContext;
    private Runnable mRefreshRunnable;
    private BluetoothHeadsetDeviceV3 mScoConnectedDevice;

    public BluetoothHeadsetDetectorV3(Context context, AudioDeviceSwitcher.Config config) {
        super(AudioRouteType.Bluetooth);
        this.mBluetoothHeadsetDeviceV3List = new CopyOnWriteArrayList();
        this.mBluetoothDeviceList = new CopyOnWriteArrayList();
        this.mScoConnectedDevice = null;
        this.mRefreshRunnable = new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothHeadsetDetectorV3.1
            @Override // java.lang.Runnable
            public void run() {
                BluetoothHeadsetDetectorV3.this.refreshBluetoothHeadsetConnection();
            }
        };
        this.mContext = context;
        this.mConfig = config;
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
                this.mBluetoothAdapter.getProfileProxy(this.mContext, new BluetoothProfile.ServiceListener() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothHeadsetDetectorV3.2
                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceConnected(int profile, BluetoothProfile proxy) {
                        Logging.i(BluetoothHeadsetDetectorV3.TAG, "BluetoothProfile.HEADSET onServiceConnected");
                        if (proxy instanceof BluetoothHeadset) {
                            BluetoothHeadsetDetectorV3.this.mBluetoothHeadset = (BluetoothHeadset) proxy;
                            BluetoothHeadsetDetectorV3.this.refreshBluetoothHeadsetConnection();
                        }
                    }

                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceDisconnected(int profile) {
                        Logging.i(BluetoothHeadsetDetectorV3.TAG, "BluetoothProfile.HEADSET onServiceDisconnected");
                    }
                }, 1);
            }
        } catch (Throwable e) {
            Logging.i(TAG, "getProfileProxy error: " + e.getMessage());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void refreshScoAudioConnection(BluetoothDevice device, boolean isScoConnected) {
        Logging.i(TAG, "refreshScoAudioConnection connected: " + isScoConnected);
        if (isScoConnected) {
            BluetoothHeadsetDeviceV3 bluetoothHeadsetDeviceV3FindDeviceV3 = findDeviceV3(device);
            this.mScoConnectedDevice = bluetoothHeadsetDeviceV3FindDeviceV3;
            if (bluetoothHeadsetDeviceV3FindDeviceV3 != null) {
                bluetoothHeadsetDeviceV3FindDeviceV3.handleScoAudioConnected();
                return;
            }
            return;
        }
        BluetoothHeadsetDeviceV3 bluetoothHeadsetDeviceV3 = this.mScoConnectedDevice;
        if (bluetoothHeadsetDeviceV3 != null && bluetoothHeadsetDeviceV3.isSameBluetoothDevice(device)) {
            this.mScoConnectedDevice.handleScoAudioDisconnected();
            this.mScoConnectedDevice = null;
        }
    }

    public void refreshBluetoothHeadsetConnection() {
        try {
            if (this.mBluetoothHeadset != null) {
                List<BluetoothDevice> connectedDeviceList = this.mBluetoothHeadset.getConnectedDevices();
                List<BluetoothDevice> tempList = new ArrayList<>(this.mBluetoothDeviceList);
                if (connectedDeviceList != null && connectedDeviceList.size() > 0) {
                    for (BluetoothDevice device : connectedDeviceList) {
                        if (device != null && !this.mBluetoothDeviceList.contains(device)) {
                            BluetoothHeadsetDeviceV3 deviceV3 = new BluetoothHeadsetDeviceV3(this.mContext, device);
                            deviceV3.setBluetoothHeadset(this.mBluetoothHeadset);
                            this.mBluetoothHeadsetDeviceV3List.add(deviceV3);
                            onDeviceAvailable(deviceV3);
                        } else {
                            tempList.remove(device);
                        }
                    }
                    if (tempList.size() > 0) {
                        for (BluetoothDevice device2 : tempList) {
                            if (device2 != null) {
                                AbstractAudioDevice deviceV32 = new BluetoothHeadsetDeviceV3(this.mContext, device2);
                                this.mBluetoothHeadsetDeviceV3List.remove(deviceV32);
                                onDeviceUnavailable(deviceV32);
                            }
                        }
                        return;
                    }
                    return;
                }
            }
            for (AbstractAudioDevice deviceV33 : this.mBluetoothHeadsetDeviceV3List) {
                if (deviceV33 != null) {
                    onDeviceUnavailable(deviceV33);
                }
            }
            this.mBluetoothHeadsetDeviceV3List.clear();
        } catch (Exception e) {
            Logging.i(TAG, "Bluetooth headset has exp, " + e.getMessage());
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.BaseBluetoothDetector
    protected boolean isBluetoothOn() {
        for (BluetoothHeadsetDeviceV3 deviceV3 : this.mBluetoothHeadsetDeviceV3List) {
            if (deviceV3 != null) {
                return deviceV3.isBluetoothOn();
            }
        }
        return false;
    }

    private BluetoothHeadsetDeviceV3 findDeviceV3(BluetoothDevice bluetoothDevice) {
        for (BluetoothHeadsetDeviceV3 headsetDeviceV3 : this.mBluetoothHeadsetDeviceV3List) {
            if (headsetDeviceV3 != null && headsetDeviceV3.isSameBluetoothDevice(bluetoothDevice)) {
                return headsetDeviceV3;
            }
        }
        return null;
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
                Logging.i(BluetoothHeadsetDetectorV3.TAG, StringUtils.getAppendString("BluetoothAdapter.ACTION_STATE_CHANGED: ", BluetoothHeadsetDetectorV3.this.adapterStateToString(preState), "=>", BluetoothHeadsetDetectorV3.this.adapterStateToString(state)));
                BluetoothHeadsetDetectorV3.this.refreshBluetoothHeadsetConnectionDelay();
                return;
            }
            if (b == 1) {
                int preState2 = intent.getIntExtra("android.bluetooth.profile.extra.PREVIOUS_STATE", 0);
                int state2 = intent.getIntExtra("android.bluetooth.profile.extra.STATE", 0);
                Logging.i(BluetoothHeadsetDetectorV3.TAG, StringUtils.getAppendString("BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED: ", BluetoothHeadsetDetectorV3.this.profileStateToString(preState2), "=>", BluetoothHeadsetDetectorV3.this.profileStateToString(state2), ", device=", BluetoothHeadsetDetectorV3.this.getDeviceName(intent.getExtras())));
                BluetoothHeadsetDetectorV3.this.refreshBluetoothHeadsetConnectionDelay();
                BluetoothHeadsetDetectorV3 bluetoothHeadsetDetectorV3 = BluetoothHeadsetDetectorV3.this;
                bluetoothHeadsetDetectorV3.logBluetoothHeadsetInfo(bluetoothHeadsetDetectorV3.mBluetoothHeadset);
                return;
            }
            if (b != 2) {
                if (b == 3) {
                    int preState3 = intent.getIntExtra("android.media.extra.SCO_AUDIO_PREVIOUS_STATE", 0);
                    int state3 = intent.getIntExtra("android.media.extra.SCO_AUDIO_STATE", 0);
                    Logging.i(BluetoothHeadsetDetectorV3.TAG, StringUtils.getAppendString("AudioManager.ACTION_SCO_AUDIO_STATE_UPDATED: ", BluetoothHeadsetDetectorV3.this.audioManagerStateToString(preState3), "=>", BluetoothHeadsetDetectorV3.this.audioManagerStateToString(state3)));
                    return;
                }
                return;
            }
            int preState4 = intent.getIntExtra("android.bluetooth.profile.extra.PREVIOUS_STATE", 10);
            int state4 = intent.getIntExtra("android.bluetooth.profile.extra.STATE", 10);
            Logging.i(BluetoothHeadsetDetectorV3.TAG, StringUtils.getAppendString("BluetoothHeadset.ACTION_AUDIO_STATE_CHANGED: ", BluetoothHeadsetDetectorV3.this.headsetScoStateToString(preState4), "=>", BluetoothHeadsetDetectorV3.this.headsetScoStateToString(state4), ", device=", BluetoothHeadsetDetectorV3.this.getDeviceName(intent.getExtras())));
            BluetoothHeadsetDetectorV3.this.refreshBluetoothHeadsetConnection();
            if (state4 == 12 || state4 == 10) {
                BluetoothHeadsetDetectorV3 bluetoothHeadsetDetectorV32 = BluetoothHeadsetDetectorV3.this;
                bluetoothHeadsetDetectorV32.refreshScoAudioConnection(bluetoothHeadsetDetectorV32.getDevice(intent.getExtras()), state4 == 12);
            }
            BluetoothHeadsetDetectorV3 bluetoothHeadsetDetectorV33 = BluetoothHeadsetDetectorV3.this;
            bluetoothHeadsetDetectorV33.logBluetoothHeadsetInfo(bluetoothHeadsetDetectorV33.mBluetoothHeadset);
        }
    }
}
