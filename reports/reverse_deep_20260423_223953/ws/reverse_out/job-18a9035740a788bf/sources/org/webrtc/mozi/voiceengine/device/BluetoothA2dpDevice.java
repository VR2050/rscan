package org.webrtc.mozi.voiceengine.device;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.voiceengine.device.AbstractAudioDevice;

/* JADX INFO: loaded from: classes3.dex */
public class BluetoothA2dpDevice extends AbstractAudioDevice {
    public static final String TAG = "[ble] BluetoothA2dpDevice";
    private BluetoothA2dp mBluetoothA2dp;
    private BluetoothAdapter mBluetoothAdapter;
    private int mBluetoothState;
    private BluetoothDevice mSelectedBluetoothDevice;

    public BluetoothA2dpDevice(Context context) {
        super(context, AudioRouteType.A2dp);
        this.mBluetoothState = -1;
        try {
            BluetoothAdapter defaultAdapter = BluetoothAdapter.getDefaultAdapter();
            this.mBluetoothAdapter = defaultAdapter;
            if (defaultAdapter != null) {
                defaultAdapter.getProfileProxy(this.mContext, new BluetoothProfile.ServiceListener() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothA2dpDevice.1
                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceConnected(int profile, BluetoothProfile proxy) {
                        Logging.i(BluetoothA2dpDevice.TAG, "BluetoothProfile.A2DP onServiceConnected");
                        if (proxy instanceof BluetoothA2dp) {
                            BluetoothA2dpDevice.this.mBluetoothA2dp = (BluetoothA2dp) proxy;
                        }
                    }

                    @Override // android.bluetooth.BluetoothProfile.ServiceListener
                    public void onServiceDisconnected(int profile) {
                        Logging.i(BluetoothA2dpDevice.TAG, "BluetoothProfile.A2DP onServiceDisconnected");
                    }
                }, 2);
            }
        } catch (Throwable e) {
            Logging.i(TAG, "getProfileProxy error: " + e.getMessage());
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void activate(AbstractAudioDevice.ActivateCallback activateCallback) {
        if (activateCallback != null) {
            activateCallback.onActivateSuccess(this);
        }
        enableSpeaker(false);
        setA2dpMusicOn();
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void inactivate() {
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void checkAndReactivate() {
    }

    private void setA2dpMusicOn() {
        if (this.mSelectedBluetoothDevice == null) {
            Logging.e(TAG, "setA2dpMusicOn device is null, return.");
            return;
        }
        if (this.mBluetoothA2dp != null) {
            Logging.i(TAG, "setA2dpMusicOn device = " + this.mSelectedBluetoothDevice.getName() + ", status = " + this.mBluetoothA2dp.getConnectionState(this.mSelectedBluetoothDevice));
            if (this.mBluetoothA2dp.isA2dpPlaying(this.mSelectedBluetoothDevice)) {
                Logging.i(TAG, "this device is a2dp playing, return: " + this.mSelectedBluetoothDevice.getName());
                return;
            }
            try {
                Method connect = BluetoothA2dp.class.getDeclaredMethod("setActiveDevice", BluetoothDevice.class);
                connect.setAccessible(true);
                connect.invoke(this.mBluetoothA2dp, this.mSelectedBluetoothDevice);
            } catch (Exception e) {
                Logging.e(TAG, "setA2dpMusicOn exception:" + e.getMessage());
            }
        }
    }

    private void setA2dpMusicOff() {
        if (this.mBluetoothA2dp != null) {
            try {
                Method connect = BluetoothA2dp.class.getDeclaredMethod("setActiveDevice", BluetoothDevice.class);
                connect.setAccessible(true);
                connect.invoke(this.mBluetoothA2dp, (BluetoothDevice) null);
            } catch (Exception e) {
                Logging.e(TAG, "setA2dpMusicOff exception:" + e.getMessage());
            }
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public String getName() {
        try {
            return this.mSelectedBluetoothDevice == null ? "" : this.mSelectedBluetoothDevice.getName();
        } catch (Exception e) {
            Logging.e(TAG, "getName exception:" + e.getMessage());
            return "";
        }
    }

    public boolean isBluetoothOn() {
        try {
            return this.mBluetoothState < 0 ? this.mBluetoothAdapter != null && this.mBluetoothAdapter.isEnabled() && this.mBluetoothAdapter.getState() == 12 : this.mBluetoothState == 12;
        } catch (Exception e) {
            Logging.w(TAG, "Bluetooth has exp");
            return false;
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public int getPreferAudioMode() {
        return 0;
    }

    public boolean checkBluetoothA2dpConnection(BluetoothA2dp bluetoothA2dp, BluetoothHeadset bluetoothHeadset) {
        List<BluetoothDevice> list2;
        if (this.mBluetoothAdapter == null || !isBluetoothOn()) {
            return false;
        }
        if (bluetoothA2dp != null) {
            try {
                List<BluetoothDevice> list1 = bluetoothA2dp.getConnectedDevices();
                if (list1 != null) {
                    if (bluetoothHeadset != null && (list2 = bluetoothHeadset.getConnectedDevices()) != null) {
                        for (BluetoothDevice hasScoDevice : list2) {
                            list1.remove(hasScoDevice);
                        }
                    }
                    if (list1.size() > 0) {
                        boolean isPlaying = false;
                        Iterator<BluetoothDevice> it = list1.iterator();
                        while (true) {
                            if (!it.hasNext()) {
                                break;
                            }
                            BluetoothDevice device = it.next();
                            if (bluetoothA2dp.isA2dpPlaying(device)) {
                                isPlaying = true;
                                this.mSelectedBluetoothDevice = device;
                                break;
                            }
                        }
                        if (!isPlaying) {
                            this.mSelectedBluetoothDevice = list1.get(0);
                            return true;
                        }
                        return true;
                    }
                }
            } catch (Exception e) {
                Logging.w(TAG, "Bluetooth a2dp has exp");
            }
        }
        this.mSelectedBluetoothDevice = null;
        return false;
    }

    public void setBluetoothState(int state) {
        this.mBluetoothState = state;
    }
}
