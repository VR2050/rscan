package org.webrtc.mozi.voiceengine.device;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.content.Context;
import java.util.Iterator;
import java.util.List;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.ThreadExecutor;
import org.webrtc.mozi.voiceengine.device.AbstractAudioDevice;

/* JADX INFO: loaded from: classes3.dex */
public class BluetoothHeadsetDevice extends AbstractAudioDevice {
    private static final String TAG = "[ble] BluetoothHeadsetDeviceV2";
    private static final int TRY_CONNECT_SCO_TIMES = 3;
    private static final int TRY_RECONNECT_SCO_TIMES = 2;
    private boolean isActivated;
    private boolean isDeactivatingSco;
    private AbstractAudioDevice.ActivateCallback mActivateCallback;
    private final Runnable mActivateCallbackRunnable;
    private BluetoothAdapter mBluetoothAdapter;
    private int mBluetoothAudioState;
    private int mBluetoothState;
    private final boolean mEnableReConnectBluetoothSco;
    private BluetoothDevice mSelectedBluetoothDevice;
    private int tryConnectScoTimes;
    private int tryReConnectScoTimes;

    private class ActivateCallbackRunnable implements Runnable {
        private ActivateCallbackRunnable() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Logging.i(BluetoothHeadsetDevice.TAG, "ActivateCallbackRunnable run");
            if (BluetoothHeadsetDevice.this.isScoAudioConnected()) {
                BluetoothHeadsetDevice.this.handleScoAudioConnected();
            } else if (BluetoothHeadsetDevice.this.isScoAudioDisconnected()) {
                BluetoothHeadsetDevice.this.handleScoAudioDisconnected();
            }
        }
    }

    public void handleScoAudioConnected() {
        Logging.i(TAG, "handleScoAudioConnected");
        AbstractAudioDevice.ActivateCallback activateCallback = this.mActivateCallback;
        if (activateCallback != null) {
            activateCallback.onActivateSuccess(this);
            this.mActivateCallback = null;
            ThreadExecutor.getMainHandler().removeCallbacks(this.mActivateCallbackRunnable);
        }
        this.tryConnectScoTimes = 0;
        this.tryReConnectScoTimes = 2;
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
            ThreadExecutor.getMainHandler().postDelayed(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.BluetoothHeadsetDevice.1
                @Override // java.lang.Runnable
                public void run() {
                    Logging.i(BluetoothHeadsetDevice.TAG, "handleScoAudioDisconnected try to reconnect startBluetoothSco");
                    if (!BluetoothHeadsetDevice.this.isActivated) {
                        Logging.i(BluetoothHeadsetDevice.TAG, "handleScoAudioDisconnected has inactivated return");
                        ThreadExecutor.getMainHandler().removeCallbacks(BluetoothHeadsetDevice.this.mActivateCallbackRunnable);
                    } else if (!BluetoothHeadsetDevice.this.isScoAudioConnected()) {
                        BluetoothHeadsetDevice.this.startBluetoothSco();
                        BluetoothHeadsetDevice.this.checkScoAudioStateDelay();
                    } else {
                        Logging.i(BluetoothHeadsetDevice.TAG, "bluetooth sco already connected, skip startBluetoothSco");
                    }
                }
            }, 500L);
            return;
        }
        if (!this.isDeactivatingSco) {
            Logging.i(TAG, "handleScoAudioDisconnected onDeviceDeactivate");
            if (this.mEnableReConnectBluetoothSco && this.tryReConnectScoTimes > 0) {
                startBluetoothSco();
                this.tryReConnectScoTimes--;
                return;
            } else {
                onDeviceDeactivate();
                return;
            }
        }
        Logging.i(TAG, "handleScoAudioDisconnected stopBluetoothSco");
        this.isDeactivatingSco = false;
    }

    public BluetoothHeadsetDevice(Context context, boolean enableReConnectBluetoothSco) {
        super(context, AudioRouteType.Bluetooth);
        this.mBluetoothAdapter = null;
        this.mBluetoothAudioState = -1;
        this.mBluetoothState = -1;
        this.mActivateCallback = null;
        this.mActivateCallbackRunnable = new ActivateCallbackRunnable();
        this.mSelectedBluetoothDevice = null;
        this.isDeactivatingSco = false;
        this.tryConnectScoTimes = 0;
        this.isActivated = false;
        this.tryReConnectScoTimes = 0;
        this.mEnableReConnectBluetoothSco = enableReConnectBluetoothSco;
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
        this.tryConnectScoTimes = 3;
        startBluetoothSco();
        checkScoAudioStateDelay();
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
        try {
            int audioMode = this.mAudioManager.getMode();
            boolean isSpeakerPhoneOn = this.mAudioManager.isSpeakerphoneOn();
            boolean isScoOn = this.mAudioManager.isBluetoothScoOn();
            Logging.i(TAG, "current audioMode: " + audioMode + ", isSpeakerPhoneOn: " + isSpeakerPhoneOn + ", scoOn: " + isScoOn);
            if (audioMode != getPreferAudioMode()) {
                this.mAudioManager.setMode(getPreferAudioMode());
            }
            if (!isScoOn) {
                inactivate();
                activate(null);
            }
        } catch (Exception e) {
            Logging.e(TAG, "checkAndReactivate error:" + e.getMessage());
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

    public boolean isScoAudioConnected() {
        return this.mBluetoothAudioState == 1;
    }

    public boolean isScoAudioDisconnected() {
        return this.mBluetoothAudioState == 0;
    }

    public void checkScoAudioStateDelay() {
        Logging.i(TAG, "checkScoAudioStateDelay");
        ThreadExecutor.getMainHandler().removeCallbacks(this.mActivateCallbackRunnable);
        ThreadExecutor.getMainHandler().postDelayed(this.mActivateCallbackRunnable, 4000L);
    }

    public boolean isBluetoothOn() {
        try {
            return this.mBluetoothState < 0 ? this.mBluetoothAdapter != null && this.mBluetoothAdapter.isEnabled() && this.mBluetoothAdapter.getState() == 12 : this.mBluetoothState == 12;
        } catch (Exception e) {
            Logging.w(TAG, "Bluetooth has exp, " + e.getMessage());
            return false;
        }
    }

    public boolean checkBluetoothScoConnection(BluetoothHeadset bluetoothHeadset) {
        if (this.mBluetoothAdapter == null || !isBluetoothOn()) {
            return false;
        }
        if (bluetoothHeadset != null) {
            try {
                List<BluetoothDevice> list = bluetoothHeadset.getConnectedDevices();
                if (list == null || list.size() == 0) {
                    Logging.i(TAG, "checkBluetoothScoConnection no connected devices");
                } else {
                    updateSelectedDevice(bluetoothHeadset, list);
                    return true;
                }
            } catch (Exception e) {
                Logging.w(TAG, "Bluetooth headset has exp, " + e.getMessage());
            }
        }
        this.mSelectedBluetoothDevice = null;
        return false;
    }

    private void updateSelectedDevice(BluetoothHeadset bluetoothHeadset, List<BluetoothDevice> list) {
        boolean isAudioConnected = false;
        Iterator<BluetoothDevice> it = list.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            BluetoothDevice device = it.next();
            if (device != null && bluetoothHeadset.isAudioConnected(device)) {
                isAudioConnected = true;
                this.mSelectedBluetoothDevice = device;
                break;
            }
        }
        if (!isAudioConnected) {
            this.mSelectedBluetoothDevice = list.get(0);
        }
    }

    public void setBluetoothState(int state) {
        this.mBluetoothState = state;
    }

    public void setAudioState(int state) {
        this.mBluetoothAudioState = state;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startBluetoothSco() {
        Logging.i(TAG, "startBluetoothSco");
        try {
            this.mAudioManager.startBluetoothSco();
            this.mAudioManager.setBluetoothScoOn(true);
        } catch (Throwable e) {
            Logging.i(TAG, "startBluetoothSco error " + e.getMessage());
        }
    }

    private void stopBluetoothSco() {
        Logging.i(TAG, "stopBluetoothSco");
        try {
            this.mAudioManager.stopBluetoothSco();
            this.mAudioManager.setBluetoothScoOn(false);
        } catch (Throwable e) {
            Logging.i(TAG, "startBluetoothSco error " + e.getMessage());
        }
    }
}
