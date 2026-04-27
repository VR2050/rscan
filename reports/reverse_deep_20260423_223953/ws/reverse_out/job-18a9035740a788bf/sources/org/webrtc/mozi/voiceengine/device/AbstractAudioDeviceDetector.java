package org.webrtc.mozi.voiceengine.device;

import java.util.LinkedList;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public abstract class AbstractAudioDeviceDetector {
    private List<AbstractAudioDevice> mAvailableDevicesList = new LinkedList();
    private DetectCallback mCallback;
    protected AudioRouteType mType;

    public interface DetectCallback {
        void onDeviceAvailable(AbstractAudioDevice abstractAudioDevice);

        void onDeviceUnavailable(AbstractAudioDevice abstractAudioDevice);
    }

    public abstract void startDetect();

    public abstract void stopDetect();

    public AbstractAudioDeviceDetector(AudioRouteType type) {
        this.mType = type;
    }

    public AudioRouteType getType() {
        return this.mType;
    }

    public void setDetectCallback(DetectCallback callback) {
        this.mCallback = callback;
    }

    protected void onDeviceAvailable(AbstractAudioDevice device) {
        if (device == null || this.mAvailableDevicesList.contains(device)) {
            return;
        }
        this.mAvailableDevicesList.add(device);
        DetectCallback detectCallback = this.mCallback;
        if (detectCallback != null) {
            detectCallback.onDeviceAvailable(device);
        }
    }

    protected void onDeviceUnavailable(AbstractAudioDevice device) {
        if (device == null || !this.mAvailableDevicesList.contains(device)) {
            return;
        }
        this.mAvailableDevicesList.remove(device);
        DetectCallback detectCallback = this.mCallback;
        if (detectCallback != null) {
            detectCallback.onDeviceUnavailable(device);
        }
    }

    public List<AbstractAudioDevice> getAvailableDeviceList() {
        return this.mAvailableDevicesList;
    }
}
