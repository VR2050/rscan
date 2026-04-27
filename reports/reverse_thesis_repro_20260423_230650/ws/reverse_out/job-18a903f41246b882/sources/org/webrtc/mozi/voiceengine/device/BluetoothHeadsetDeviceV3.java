package org.webrtc.mozi.voiceengine.device;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.content.Context;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.ThreadExecutor;
import org.webrtc.mozi.voiceengine.device.AbstractAudioDevice;

/* JADX INFO: loaded from: classes3.dex */
public class BluetoothHeadsetDeviceV3 extends AbstractAudioDevice {
    private static final String TAG = "[ble] BluetoothHeadsetDeviceV3";
    private static final int TRY_CONNECT_SCO_AFTER_DEACTIVATE_TIMES = 3;
    private static final int TRY_CONNECT_SCO_TIMES = 3;
    private boolean isActivated;
    private boolean isDeactivatingSco;
    private AbstractAudioDevice.ActivateCallback mActivateCallback;
    private final Runnable mActivateCallbackRunnable;
    private BluetoothAdapter mBluetoothAdapter;
    private BluetoothDevice mBluetoothDevice;
    private BluetoothHeadset mBluetoothHeadset;
    private boolean mIsGoingToConnect;
    private int tryConnectScoTimes;

    private class ActivateCallbackRunnable implements Runnable {
        private ActivateCallbackRunnable() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Logging.i(BluetoothHeadsetDeviceV3.TAG, "ActivateCallbackRunnable run");
            if (BluetoothHeadsetDeviceV3.this.isScoAudioConnected()) {
                BluetoothHeadsetDeviceV3.this.handleScoAudioConnected();
            } else {
                BluetoothHeadsetDeviceV3.this.handleScoAudioDisconnected();
            }
        }
    }

    public void handleScoAudioConnected() {
        Logging.i(TAG, "handleScoAudioConnected");
        AbstractAudioDevice.ActivateCallback activateCallback = this.mActivateCallback;
        if (activateCallback != null) {
            activateCallback.onActivateSuccess(this);
            this.mActivateCallback = null;
        }
        ThreadExecutor.getMainHandler().removeCallbacks(this.mActivateCallbackRunnable);
        this.tryConnectScoTimes = 0;
    }

    public void handleScoAudioDisconnected() {
        Logging.i(TAG, "handleScoAudioDisconnected");
        if (this.mActivateCallback != null) {
            if (this.tryConnectScoTimes <= 0) {
                Logging.i(TAG, "handleScoAudioDisconnected onActivateFail");
                this.mActivateCallback.onActivateFail();
                this.mActivateCallback = null;
                ThreadExecutor.getMainHandler().removeCallbacks(this.mActivateCallbackRunnable);
                return;
            }
            Logging.i(TAG, "handleScoAudioDisconnected try to reconnect index = " + this.tryConnectScoTimes);
            this.tryConnectScoTimes = this.tryConnectScoTimes + (-1);
            activateWithDelayMillis("handleScoAudioDisconnected try to reconnect startBluetoothSco", "handleScoAudioDisconnected has inactivated return");
            return;
        }
        if (this.isDeactivatingSco) {
            Logging.i(TAG, "handleScoAudioDisconnected stopBluetoothSco");
            this.isDeactivatingSco = false;
        } else {
            onDeviceDeactivate();
        }
    }

    private void activateWithDelayMillis(final String msgWhenRun, final String msgWhenRunInactivated) {
        ThreadExecutor.getMainHandler().postDelayed(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothHeadsetDeviceV3.1
            @Override // java.lang.Runnable
            public void run() {
                Logging.i(BluetoothHeadsetDeviceV3.TAG, msgWhenRun);
                if (BluetoothHeadsetDeviceV3.this.isActivated) {
                    BluetoothHeadsetDeviceV3.this.startBluetoothSco();
                    BluetoothHeadsetDeviceV3.this.checkScoAudioStateDelay();
                } else {
                    Logging.i(BluetoothHeadsetDeviceV3.TAG, msgWhenRunInactivated);
                    ThreadExecutor.getMainHandler().removeCallbacks(BluetoothHeadsetDeviceV3.this.mActivateCallbackRunnable);
                }
            }
        }, 500L);
    }

    public BluetoothHeadsetDeviceV3(Context context, BluetoothDevice bluetoothDevice) {
        super(context, AudioRouteType.Bluetooth);
        this.mBluetoothAdapter = null;
        this.mBluetoothHeadset = null;
        this.mIsGoingToConnect = false;
        this.mActivateCallback = null;
        this.mActivateCallbackRunnable = new ActivateCallbackRunnable();
        this.isDeactivatingSco = false;
        this.tryConnectScoTimes = 0;
        this.isActivated = false;
        this.mBluetoothDevice = bluetoothDevice;
        try {
            this.mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        } catch (Exception e) {
            Logging.w(TAG, "getDefaultAdapter has exp, " + e.getMessage());
        }
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void activate(AbstractAudioDevice.ActivateCallback activateCallback) {
        Logging.i(TAG, "BluetoothHeadsetDevice activate");
        this.isActivated = true;
        this.mActivateCallback = activateCallback;
        this.isDeactivatingSco = false;
        this.mIsGoingToConnect = true;
        this.tryConnectScoTimes = 3;
        activateWithDelayMillis("activate startBluetoothSco", "activate has inactivated return");
        enableSpeaker(false);
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void inactivate() {
        Logging.i(TAG, "BluetoothHeadsetDevice inactivate");
        this.isActivated = false;
        this.tryConnectScoTimes = 0;
        this.isDeactivatingSco = true;
        stopBluetoothSco();
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public void checkAndReactivate() {
    }

    @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice
    public String getName() {
        try {
            return this.mBluetoothDevice == null ? "" : this.mBluetoothDevice.getName();
        } catch (Exception e) {
            Logging.e(TAG, "getName exception:" + e.getMessage());
            return "";
        }
    }

    public void checkScoAudioStateDelay() {
        Logging.i(TAG, "checkScoAudioStateDelay");
        ThreadExecutor.getMainHandler().removeCallbacks(this.mActivateCallbackRunnable);
        ThreadExecutor.getMainHandler().postDelayed(this.mActivateCallbackRunnable, 4000L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startBluetoothSco() {
        Logging.i(TAG, "startBluetoothSco");
        try {
            if (this.mBluetoothHeadset != null && this.mBluetoothDevice != null) {
                this.mIsGoingToConnect = false;
                boolean result = this.mBluetoothHeadset.startVoiceRecognition(this.mBluetoothDevice);
                Logging.i(TAG, "startBluetoothSco result = " + result);
            }
        } catch (Throwable e) {
            Logging.i(TAG, "startBluetoothSco error " + e.getMessage());
        }
    }

    private void stopBluetoothSco() {
        Logging.i(TAG, "stopBluetoothSco");
        try {
            if (this.mBluetoothHeadset != null && this.mBluetoothDevice != null) {
                this.mBluetoothHeadset.stopVoiceRecognition(this.mBluetoothDevice);
            }
        } catch (Throwable e) {
            Logging.i(TAG, "startBluetoothSco error " + e.getMessage());
        }
    }

    public void setBluetoothHeadset(BluetoothHeadset bluetoothHeadset) {
        this.mBluetoothHeadset = bluetoothHeadset;
        if (this.mIsGoingToConnect) {
            Logging.i(TAG, "setBluetoothHeadset startBluetoothSco");
            startBluetoothSco();
        }
    }

    public boolean isSameBluetoothDevice(BluetoothDevice device) {
        BluetoothDevice bluetoothDevice = this.mBluetoothDevice;
        return bluetoothDevice != null && bluetoothDevice.equals(device);
    }

    public boolean isScoAudioConnected() {
        BluetoothDevice bluetoothDevice;
        BluetoothHeadset bluetoothHeadset = this.mBluetoothHeadset;
        if (bluetoothHeadset != null && (bluetoothDevice = this.mBluetoothDevice) != null) {
            return bluetoothHeadset.isAudioConnected(bluetoothDevice);
        }
        return false;
    }

    public boolean isBluetoothOn() {
        try {
            if (this.mBluetoothAdapter == null || !this.mBluetoothAdapter.isEnabled()) {
                return false;
            }
            return this.mBluetoothAdapter.getState() == 12;
        } catch (Exception e) {
            Logging.w(TAG, "Bluetooth has exp, " + e.getMessage());
            return false;
        }
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        BluetoothHeadsetDeviceV3 that = (BluetoothHeadsetDeviceV3) o;
        return this.mBluetoothDevice.equals(that.mBluetoothDevice);
    }

    public int hashCode() {
        return this.mBluetoothDevice.hashCode();
    }
}
