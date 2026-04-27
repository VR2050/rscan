package org.webrtc.mozi;

import java.util.List;
import org.webrtc.mozi.CameraEnumerationAndroid;

/* JADX INFO: loaded from: classes3.dex */
public class CameraFrameRateSelector implements CameraEnumerationAndroid.FrameRateDelegate {
    private final String cameraTag;

    public CameraFrameRateSelector(String cameraTag) {
        this.cameraTag = cameraTag;
    }

    @Override // org.webrtc.mozi.CameraEnumerationAndroid.FrameRateDelegate
    public CameraEnumerationAndroid.CaptureFormat.FramerateRange getClosestSupportedFramerateRange(List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> supportedFramerates, int requestedFps) {
        if (supportedFramerates == null || supportedFramerates.size() <= 0) {
            Logging.d(this.cameraTag, "supportedFrameRates null");
            return null;
        }
        int targetFps = requestedFps * 1000;
        boolean hasHigherFps = false;
        if (supportedFramerates.size() <= 0) {
            return null;
        }
        CameraEnumerationAndroid.CaptureFormat.FramerateRange range = supportedFramerates.get(0);
        int minDiff = Math.abs(range.min - targetFps) + Math.abs(range.max - targetFps);
        CameraEnumerationAndroid.CaptureFormat.FramerateRange targetFpsRange = range;
        if (range.max >= targetFps) {
            hasHigherFps = true;
        }
        for (int i = 1; i < supportedFramerates.size(); i++) {
            CameraEnumerationAndroid.CaptureFormat.FramerateRange range2 = supportedFramerates.get(i);
            if (!hasHigherFps || range2.max >= targetFps) {
                int currentDiff = Math.abs(range2.min - targetFps) + Math.abs(range2.max - targetFps);
                if (!hasHigherFps && range2.max >= targetFps) {
                    targetFpsRange = range2;
                    minDiff = currentDiff;
                    hasHigherFps = true;
                } else if (currentDiff < minDiff) {
                    targetFpsRange = range2;
                    minDiff = currentDiff;
                }
            }
        }
        return targetFpsRange;
    }
}
