package org.webrtc.mozi;

import java.util.List;
import org.webrtc.mozi.CameraEnumerationAndroid;
import org.webrtc.mozi.CameraVideoCapturer;

/* JADX INFO: loaded from: classes3.dex */
public interface CameraEnumerator {
    CameraVideoCapturer createCapturer(String str, CameraVideoCapturer.CameraEventsHandler cameraEventsHandler);

    String[] getDeviceNames();

    List<CameraEnumerationAndroid.CaptureFormat> getSupportedFormats(String str);

    boolean isBackFacing(String str);

    boolean isFrontFacing(String str);
}
