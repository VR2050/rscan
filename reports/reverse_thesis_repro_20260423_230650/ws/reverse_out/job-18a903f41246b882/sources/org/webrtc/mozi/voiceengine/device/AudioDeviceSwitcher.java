package org.webrtc.mozi.voiceengine.device;

import android.content.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.ToIntFunction;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.utils.CollectionUtils;
import org.webrtc.mozi.utils.ThreadExecutor;
import org.webrtc.mozi.voiceengine.device.AbstractAudioDevice;
import org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector;

/* JADX INFO: loaded from: classes3.dex */
public class AudioDeviceSwitcher {
    public static final String AUDIO_DEVICE_SWITCH_SOURCE_APP = "app";
    public static final String AUDIO_DEVICE_SWITCH_SOURCE_USER = "user";
    private static final String AUDIO_DEVICE_SWITCH_TARGET_DEFAULT = "default";
    private static final String TAG = "AudioDeviceSwitcher";
    private AbstractAudioDevice mActiveDevice;
    private List<AbstractAudioDeviceDetector> mAudioDeviceDetectors;
    private boolean mAutoSwitchEnbaled;
    private List<AutoSwitchReference> mAutoSwitchReferences;
    private Config mConfig;
    private Context mContext;
    private AudioRouteType mDefaultAudioRouteType;
    private AbstractAudioDeviceDetector.DetectCallback mDetectCallback;
    private AbstractAudioDevice.DeviceDeactivateCallback mDeviceDeactivateCallback;
    private List<AbstractAudioDevice> mDevices;
    private List<AudioDeviceListener> mListeners;

    public static class Config {
        boolean enableReConnectBluetoothSco;
        boolean isUseBluetoothDetectorV3;
        boolean optimizeBluetoothSco;
        boolean resetAudioDevice;

        public Config(boolean isUseBluetoothDetectorV3, boolean optimizeBluetoothSco, boolean resetAudioDevice, boolean enableReConnectBluetoothSco) {
            this.isUseBluetoothDetectorV3 = isUseBluetoothDetectorV3;
            this.optimizeBluetoothSco = optimizeBluetoothSco;
            this.resetAudioDevice = resetAudioDevice;
            this.enableReConnectBluetoothSco = enableReConnectBluetoothSco;
        }
    }

    public class AutoSwitchReference {
        public AutoSwitchReference() {
        }

        public void release() {
            AudioDeviceSwitcher.this.releaseAutoSwitch(this);
        }
    }

    private static final class SingleInstanceHolder {
        private static final AudioDeviceSwitcher INSTANCE = new AudioDeviceSwitcher();

        private SingleInstanceHolder() {
        }
    }

    public static AudioDeviceSwitcher getInstance() {
        return SingleInstanceHolder.INSTANCE;
    }

    private AudioDeviceSwitcher() {
        this.mDefaultAudioRouteType = AudioRouteType.Speakerphone;
        this.mDevices = Collections.synchronizedList(new LinkedList());
        this.mListeners = Collections.synchronizedList(new LinkedList());
        this.mAudioDeviceDetectors = Collections.synchronizedList(new LinkedList());
        this.mAutoSwitchReferences = new CopyOnWriteArrayList();
        this.mAutoSwitchEnbaled = true;
        this.mConfig = new Config(false, false, false, false);
        this.mDetectCallback = new AbstractAudioDeviceDetector.DetectCallback() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher.1
            @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector.DetectCallback
            public void onDeviceAvailable(AbstractAudioDevice device) {
                AudioDeviceSwitcher.this.addAvailableDevice(device);
            }

            @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDeviceDetector.DetectCallback
            public void onDeviceUnavailable(AbstractAudioDevice device) {
                AudioDeviceSwitcher.this.removeAvailableDevice(device);
            }
        };
        this.mDeviceDeactivateCallback = new AbstractAudioDevice.DeviceDeactivateCallback() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher.2
            @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice.DeviceDeactivateCallback
            public void onDeactivateDevice(AbstractAudioDevice device) {
                AudioDeviceSwitcher.this.activateDefaultWithout(device.getAudioRouteType());
            }
        };
    }

    public void init(Context context) {
        init(context, null);
    }

    public void init(Context context, Config config) {
        if (this.mContext != null) {
            return;
        }
        this.mContext = context;
        if (config != null) {
            this.mConfig = config;
        }
        if (this.mConfig.isUseBluetoothDetectorV3) {
            Logging.i(TAG, "useV3 = true");
            this.mAudioDeviceDetectors.add(new BluetoothHeadsetDetectorV3(context, this.mConfig));
        } else {
            Logging.i(TAG, "isBluetoothAudioCompat = true");
            this.mAudioDeviceDetectors.add(new BluetoothHeadsetDetector(context, this.mConfig.optimizeBluetoothSco, this.mConfig.enableReConnectBluetoothSco));
        }
        this.mAudioDeviceDetectors.add(new WiredHeadsetDetector(context));
        this.mDevices.add(new SpeakerphoneAudioDevice(context));
        this.mDevices.add(new EarpieceAudioDevice(context));
        for (AbstractAudioDeviceDetector detector : this.mAudioDeviceDetectors) {
            if (detector != null) {
                detector.setDetectCallback(this.mDetectCallback);
            }
        }
    }

    private void startDetect() {
        for (AbstractAudioDeviceDetector detector : this.mAudioDeviceDetectors) {
            if (detector != null) {
                detector.startDetect();
            }
        }
    }

    private void stopDetect() {
        for (AbstractAudioDeviceDetector detector : this.mAudioDeviceDetectors) {
            if (detector != null) {
                detector.stopDetect();
            }
        }
    }

    public void destroy() {
        stopDetect();
        this.mContext = null;
        this.mAudioDeviceDetectors.clear();
        this.mDevices.clear();
    }

    public void setDefaultAudioType(AudioRouteType type) {
        if (type != null) {
            this.mDefaultAudioRouteType = type;
        }
    }

    public void activateDefault() {
        activateDefaultWithout(null);
    }

    public void activateDefaultWithout(AudioRouteType withoutType) {
        if (!this.mAutoSwitchEnbaled) {
            activate(this.mDefaultAudioRouteType);
            return;
        }
        ensureDevicesEnabled();
        List<AudioRouteType> audioRouteTypeList = new ArrayList<>();
        if (AudioRouteType.WiredHeadset != withoutType) {
            audioRouteTypeList.add(AudioRouteType.WiredHeadset);
        }
        if (AudioRouteType.Bluetooth != withoutType) {
            audioRouteTypeList.add(AudioRouteType.Bluetooth);
        }
        audioRouteTypeList.add(this.mDefaultAudioRouteType);
        activateDeviceFromList(audioRouteTypeList);
    }

    private void ensureDevicesEnabled() {
        Iterator<AbstractAudioDevice> iterator = this.mDevices.iterator();
        while (iterator.hasNext()) {
            AbstractAudioDevice device = iterator.next();
            if (device == null || !device.isEnabled()) {
                iterator.remove();
            }
        }
    }

    public void addListener(AudioDeviceListener listener) {
        if (listener != null && !this.mListeners.contains(listener)) {
            this.mListeners.add(listener);
        }
    }

    public void removeListener(AudioDeviceListener listener) {
        if (listener != null) {
            this.mListeners.remove(listener);
        }
    }

    public boolean activate(AudioRouteType audioRouteType) {
        return activateDevice(findDevice(audioRouteType));
    }

    public boolean activate(AudioDeviceInfo audioDeviceInfo, String source) {
        for (AbstractAudioDevice device : this.mDevices) {
            if (device != null && device.getName() != null && audioDeviceInfo.getName() != null && device.getName().equals(audioDeviceInfo.getName())) {
                return activateDevice(device);
            }
        }
        return false;
    }

    private boolean activateDevice(final AbstractAudioDevice device) {
        if (device == null || !device.isEnabled()) {
            return false;
        }
        final AbstractAudioDevice oldDevice = this.mActiveDevice;
        AbstractAudioDevice abstractAudioDevice = this.mActiveDevice;
        if (abstractAudioDevice != device && abstractAudioDevice != null) {
            abstractAudioDevice.inactivate();
            this.mActiveDevice = null;
        }
        Logging.i(TAG, "try activate1: " + getActiveAudioRouteType() + "=>" + device.getAudioRouteType());
        device.activate(new AbstractAudioDevice.ActivateCallback() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher.3
            @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice.ActivateCallback
            public void onActivateSuccess(AbstractAudioDevice newDevice) {
                if (newDevice != null) {
                    Logging.i(AudioDeviceSwitcher.TAG, "try activate1 success = " + newDevice.getAudioRouteType());
                    AudioDeviceSwitcher.this.changeDevice(oldDevice, newDevice);
                }
            }

            @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice.ActivateCallback
            public void onActivateFail() {
                Logging.i(AudioDeviceSwitcher.TAG, "try activate1 fail");
                AudioDeviceSwitcher.this.activateDefaultWithout(device.getAudioRouteType());
            }
        });
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void activateDeviceFromList(final List<AudioRouteType> deviceTypeList) {
        if (deviceTypeList == null || deviceTypeList.size() == 0) {
            return;
        }
        final AudioRouteType audioRouteType = deviceTypeList.get(0);
        AbstractAudioDevice device = findDevice(audioRouteType);
        if (device == null || !device.isEnabled()) {
            deviceTypeList.remove(audioRouteType);
            activateDeviceFromList(deviceTypeList);
            return;
        }
        Logging.i(TAG, "try activate2: " + getActiveAudioRouteType() + "=>" + device.getAudioRouteType());
        final AbstractAudioDevice oldDevice = this.mActiveDevice;
        AbstractAudioDevice abstractAudioDevice = this.mActiveDevice;
        if (abstractAudioDevice != device && abstractAudioDevice != null) {
            abstractAudioDevice.inactivate();
            this.mActiveDevice = null;
        }
        device.activate(new AbstractAudioDevice.ActivateCallback() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher.4
            @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice.ActivateCallback
            public void onActivateSuccess(AbstractAudioDevice newDevice) {
                if (newDevice != null) {
                    Logging.i(AudioDeviceSwitcher.TAG, "try activate2 success = " + newDevice.getAudioRouteType());
                    AudioDeviceSwitcher.this.changeDevice(oldDevice, newDevice);
                }
            }

            @Override // org.webrtc.mozi.voiceengine.device.AbstractAudioDevice.ActivateCallback
            public void onActivateFail() {
                Logging.i(AudioDeviceSwitcher.TAG, "try activate2 fail");
                deviceTypeList.remove(audioRouteType);
                AudioDeviceSwitcher.this.activateDeviceFromList(deviceTypeList);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changeDevice(AbstractAudioDevice oldDevice, AbstractAudioDevice newDevice) {
        this.mActiveDevice = newDevice;
        newDevice.setDeviceDeactivateCallback(this.mDeviceDeactivateCallback);
        if (oldDevice != newDevice) {
            for (AudioDeviceListener listener : this.mListeners) {
                if (listener != null) {
                    listener.onAudioDeviceChange(newDevice);
                    if (listener instanceof AudioDeviceListenerV2) {
                        ((AudioDeviceListenerV2) listener).onAudioDeviceChange(oldDevice, newDevice);
                    }
                }
            }
        }
        outputDevices();
    }

    private void outputDevices() {
        Iterator<AbstractAudioDevice> it = this.mDevices.iterator();
        while (it.hasNext()) {
            AbstractAudioDevice device = it.next();
            if (device != null) {
                StringBuilder sb = new StringBuilder();
                sb.append("outputdevices ");
                sb.append(device.getName());
                sb.append(",");
                sb.append(device.getAudioRouteType());
                sb.append(",");
                sb.append(device == this.mActiveDevice);
                Logging.i(TAG, sb.toString());
            }
        }
    }

    public AbstractAudioDevice findDevice(AudioRouteType type) {
        for (AbstractAudioDevice device : this.mDevices) {
            if (device != null && device.getAudioRouteType() == type) {
                return device;
            }
        }
        return null;
    }

    public AbstractAudioDevice getActiveDevice() {
        return this.mActiveDevice;
    }

    public AudioRouteType getActiveAudioRouteType() {
        AbstractAudioDevice abstractAudioDevice = this.mActiveDevice;
        return abstractAudioDevice == null ? AudioRouteType.None : abstractAudioDevice.getAudioRouteType();
    }

    public boolean needShowBtPermissionDenied() {
        for (AbstractAudioDeviceDetector device : this.mAudioDeviceDetectors) {
            if ((device instanceof BaseBluetoothDetector) && device.getType() == AudioRouteType.Bluetooth) {
                return ((BaseBluetoothDetector) device).needShowBtPermissionDenied();
            }
        }
        return false;
    }

    public AutoSwitchReference requireAutoSwitch(AudioRouteType defaultAudioRouteType) {
        boolean isFirstRequire = this.mAutoSwitchReferences.isEmpty();
        AutoSwitchReference reference = new AutoSwitchReference();
        this.mAutoSwitchReferences.add(reference);
        Logging.i(TAG, "requireAutoSwitch, current ref count: " + this.mAutoSwitchReferences.size());
        if (isFirstRequire) {
            startDetect();
            if (defaultAudioRouteType != null) {
                setDefaultAudioType(defaultAudioRouteType);
            }
            activateDefault();
        }
        return reference;
    }

    public void setAutoSwitchEnabled(boolean enabled) {
        this.mAutoSwitchEnbaled = enabled;
    }

    private boolean isAutoSwitchEnabled() {
        return this.mAutoSwitchEnbaled && !this.mAutoSwitchReferences.isEmpty();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void releaseAutoSwitch(AutoSwitchReference reference) {
        if (reference != null && this.mAutoSwitchReferences.contains(reference)) {
            this.mAutoSwitchReferences.remove(reference);
            if (this.mAutoSwitchReferences.isEmpty()) {
                resetSpeakerMode();
                stopDetect();
                AbstractAudioDevice abstractAudioDevice = this.mActiveDevice;
                if (abstractAudioDevice != null) {
                    abstractAudioDevice.inactivate();
                }
            }
            Logging.i(TAG, "releaseAutoSwitch, current ref count: " + this.mAutoSwitchReferences.size());
        }
    }

    private void resetSpeakerMode() {
        Config config = this.mConfig;
        if (config != null && config.resetAudioDevice && getActiveAudioRouteType() == AudioRouteType.Earpiece) {
            setDefaultAudioType(AudioRouteType.Speakerphone);
            for (AbstractAudioDevice device : this.mDevices) {
                if (device != null && device.getAudioRouteType() != AudioRouteType.Speakerphone && device.getAudioRouteType() != AudioRouteType.Earpiece) {
                    Logging.i(TAG, "resetSpeakerMode, type: " + device.getAudioRouteType());
                    return;
                }
            }
            ThreadExecutor.getMainHandler().postDelayed(new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher.5
                @Override // java.lang.Runnable
                public void run() {
                    if (AudioDeviceSwitcher.this.mAutoSwitchReferences.isEmpty()) {
                        AudioManagerCompat.setSpeakerphoneOn(AudioDeviceSwitcher.this.mActiveDevice.mAudioManager, true, false);
                    }
                }
            }, 1000L);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addAvailableDevice(AbstractAudioDevice device) {
        if (device != null && !this.mDevices.contains(device)) {
            this.mDevices.add(device);
            onDeviceAdd(device);
        }
    }

    private void onDeviceAdd(AbstractAudioDevice device) {
        if (device == null) {
            return;
        }
        Logging.i(TAG, "device add " + device.getAudioRouteType());
        outputDevices();
        for (AudioDeviceListener listener : this.mListeners) {
            if (listener != null) {
                listener.onAudioDeviceAvailable(device);
            }
        }
        if (!isAutoSwitchEnabled()) {
            return;
        }
        if (this.mConfig.isUseBluetoothDetectorV3) {
            for (AbstractAudioDevice audioDevice : this.mDevices) {
                if (audioDevice != null && audioDevice.getAudioRouteType() == device.getAudioRouteType()) {
                    return;
                }
            }
        }
        if (device.getAudioRouteType() == AudioRouteType.WiredHeadset) {
            activate(AudioRouteType.WiredHeadset);
        } else if (device.getAudioRouteType() == AudioRouteType.Bluetooth) {
            activate(AudioRouteType.Bluetooth);
        }
    }

    private void onDeviceRemove(AbstractAudioDevice device) {
        if (device == null) {
            return;
        }
        for (AudioDeviceListener listener : this.mListeners) {
            if (listener != null) {
                listener.onAudioDeviceUnavailable(device);
            }
        }
        Logging.i(TAG, "device remove " + device.getAudioRouteType());
        outputDevices();
        if (device == this.mActiveDevice && isAutoSwitchEnabled()) {
            activateDefault();
        }
    }

    public boolean hasType(AudioRouteType type) {
        return findDevice(type) != null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeAvailableDevice(AbstractAudioDevice device) {
        if (device != null && this.mDevices.contains(device)) {
            this.mDevices.remove(device);
            onDeviceRemove(device);
        }
    }

    public List<AudioDeviceInfo> getAllAudioDevices() {
        List<AudioDeviceInfo> list = new ArrayList<>();
        AbstractAudioDevice wired = findDevice(AudioRouteType.WiredHeadset);
        Iterator<AbstractAudioDevice> it = this.mDevices.iterator();
        while (it.hasNext()) {
            AbstractAudioDevice device = it.next();
            if (device != null && (!(device instanceof EarpieceAudioDevice) || wired == null)) {
                list.add(new AudioDeviceInfo(device, device == this.mActiveDevice));
            }
        }
        CollectionUtils.sortPriority(list, new ToIntFunction<AudioDeviceInfo>() { // from class: org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher.6
            @Override // java.util.function.ToIntFunction
            public int applyAsInt(AudioDeviceInfo audioDeviceInfo) {
                return audioDeviceInfo.getType().ordinal();
            }
        });
        return list;
    }

    public static class AudioDeviceInfo {
        boolean isUsed;
        String name;
        AudioRouteType type;

        public AudioDeviceInfo(AbstractAudioDevice device, boolean isUsed) {
            this.name = device.getName();
            this.type = device.getAudioRouteType();
            this.isUsed = isUsed;
        }

        public String toString() {
            return "AudioDeviceInfo{name='" + this.name + "', type=" + this.type + ", isUsed=" + this.isUsed + '}';
        }

        public String getName() {
            return this.name;
        }

        public AudioRouteType getType() {
            return this.type;
        }

        public boolean isUsed() {
            return this.isUsed;
        }
    }
}
