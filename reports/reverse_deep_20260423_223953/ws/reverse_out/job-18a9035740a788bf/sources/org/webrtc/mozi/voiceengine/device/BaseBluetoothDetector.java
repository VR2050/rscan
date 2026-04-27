package org.webrtc.mozi.voiceengine.device;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.os.Bundle;
import java.util.List;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.CollectionUtils;

/* JADX INFO: loaded from: classes3.dex */
public abstract class BaseBluetoothDetector extends AbstractAudioDeviceDetector {
    private static final String TAG = "[ble] BluetoothBaseDetector";
    protected BluetoothAdapter mBluetoothAdapter;
    protected BluetoothHeadset mBluetoothHeadset;

    protected abstract boolean isBluetoothOn();

    public BaseBluetoothDetector(AudioRouteType type) {
        super(type);
    }

    public boolean needShowBtPermissionDenied() {
        return isBluetoothOn() && isHeadsetConnection() && checkConnectedDevice();
    }

    private boolean isHeadsetConnection() {
        int state = -1;
        BluetoothAdapter bluetoothAdapter = this.mBluetoothAdapter;
        if (bluetoothAdapter != null) {
            try {
                state = bluetoothAdapter.getProfileConnectionState(1);
            } catch (Exception e) {
                Logging.e(TAG, e.getMessage());
            }
        }
        boolean isHeadsetConnection = state == 2;
        Logging.i(TAG, "BaseBluetoothDetector isHeadsetConnection = " + isHeadsetConnection);
        return isHeadsetConnection;
    }

    private boolean checkConnectedDevice() {
        BluetoothHeadset bluetoothHeadset = this.mBluetoothHeadset;
        if (bluetoothHeadset == null) {
            Logging.i(TAG, "BaseBluetoothDetector mBluetoothHeadset null");
            return false;
        }
        List<BluetoothDevice> deviceList = null;
        try {
            deviceList = bluetoothHeadset.getConnectedDevices();
        } catch (Exception e) {
            Logging.e(TAG, e.getMessage());
        }
        boolean noConnectedDevice = CollectionUtils.isEmpty(deviceList);
        Logging.i(TAG, "BaseBluetoothDetector noConnectedDevice = " + noConnectedDevice);
        return noConnectedDevice;
    }

    protected void logBluetoothA2dpInfo(BluetoothA2dp bluetoothA2dp) {
        if (bluetoothA2dp != null) {
            try {
                List<BluetoothDevice> deviceList = bluetoothA2dp.getConnectedDevices();
                if (deviceList != null) {
                    for (BluetoothDevice device : deviceList) {
                        if (device != null) {
                            Logging.i(TAG, "a2dp proxy : " + device.getName() + ", " + bluetoothA2dp.isA2dpPlaying(device));
                        }
                    }
                }
            } catch (Exception e) {
                Logging.e(TAG, e.getMessage());
            }
        }
    }

    protected void logBluetoothHeadsetInfo(BluetoothHeadset bluetoothHeadset) {
        if (bluetoothHeadset != null) {
            try {
                List<BluetoothDevice> deviceList = bluetoothHeadset.getConnectedDevices();
                if (deviceList != null) {
                    for (BluetoothDevice device : deviceList) {
                        if (device != null) {
                            Logging.i(TAG, "headset proxy : " + device.getName() + ", " + bluetoothHeadset.isAudioConnected(device));
                        }
                    }
                }
            } catch (Exception e) {
                Logging.e(TAG, e.getMessage());
            }
        }
    }

    protected BluetoothDevice getDevice(Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        try {
            return (BluetoothDevice) bundle.getParcelable("android.bluetooth.device.extra.DEVICE");
        } catch (Exception e) {
            Logging.e(TAG, e.getMessage());
            return null;
        }
    }

    protected String getDeviceName(Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        try {
            BluetoothDevice device = (BluetoothDevice) bundle.getParcelable("android.bluetooth.device.extra.DEVICE");
            if (device == null) {
                return null;
            }
            return device.getName();
        } catch (Exception e) {
            Logging.e(TAG, e.getMessage());
            return null;
        }
    }

    protected String adapterStateToString(int state) {
        switch (state) {
            case 10:
                return "OFF";
            case 11:
                return "TURNING_ON";
            case 12:
                return "ON";
            case 13:
                return "TURNING_OFF";
            default:
                return "INVALID";
        }
    }

    protected String profileStateToString(int state) {
        if (state == 0) {
            return "DISCONNECTED";
        }
        if (state == 1) {
            return "CONNECTING";
        }
        if (state == 2) {
            return "CONNECTED";
        }
        if (state == 3) {
            return "DISCONNECTING";
        }
        return "INVALID";
    }

    protected String a2dpStateToString(int state) {
        if (state == 10) {
            return "PLAYING";
        }
        if (state == 11) {
            return "NOT_PLAYING";
        }
        return "INVALID";
    }

    protected String audioManagerStateToString(int state) {
        if (state == -1) {
            return "ERROR";
        }
        if (state == 0) {
            return "DISCONNECTED";
        }
        if (state == 1) {
            return "CONNECTED";
        }
        if (state == 2) {
            return "CONNECTING";
        }
        return "INVALID";
    }

    protected String headsetScoStateToString(int state) {
        switch (state) {
            case 10:
                return "AUDIO_DISCONNECTED";
            case 11:
                return "AUDIO_CONNECTING";
            case 12:
                return "AUDIO_CONNECTED";
            default:
                return "INVALID";
        }
    }
}
