package org.webrtc.mozi;

import java.util.List;
import org.webrtc.mozi.CameraEnumerationAndroid;

/* JADX INFO: loaded from: classes3.dex */
public final class CameraSessionData {
    private CameraEnumerationAndroid.CaptureFormat mActualFormat;
    private List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> mSupportRange;
    private List<Size> mSupportSize;
    private CameraEnumerationAndroid.CaptureFormat mTargetFormat;

    void setTargetFormat(CameraEnumerationAndroid.CaptureFormat targetFormat) {
        this.mTargetFormat = targetFormat;
    }

    void setActualFormat(CameraEnumerationAndroid.CaptureFormat actualFormat) {
        this.mActualFormat = actualFormat;
    }

    public void setSupportSize(List<Size> supportSize) {
        this.mSupportSize = supportSize;
    }

    public void setSupportRange(List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> supportRange) {
        this.mSupportRange = supportRange;
    }

    public String getTargetResolution() {
        CameraEnumerationAndroid.CaptureFormat captureFormat = this.mTargetFormat;
        return captureFormat == null ? "" : captureFormat.toSizeString();
    }

    public String getTargetFps() {
        CameraEnumerationAndroid.CaptureFormat captureFormat = this.mTargetFormat;
        return captureFormat == null ? "" : captureFormat.framerate.toString();
    }

    public String getActualResolution() {
        CameraEnumerationAndroid.CaptureFormat captureFormat = this.mActualFormat;
        return captureFormat == null ? "" : captureFormat.toSizeString();
    }

    public String getActualFps() {
        CameraEnumerationAndroid.CaptureFormat captureFormat = this.mActualFormat;
        return captureFormat == null ? "" : captureFormat.framerate.toString();
    }

    public String getSupportSize() {
        List<Size> list = this.mSupportSize;
        if (list == null || list.size() < 1) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (Size size : this.mSupportSize) {
            if (size != null) {
                result.append(size.toString());
                result.append(",");
            }
        }
        return result.toString();
    }

    public String getSupportRange() {
        List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> list = this.mSupportRange;
        if (list == null || list.size() < 1) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (CameraEnumerationAndroid.CaptureFormat.FramerateRange range : this.mSupportRange) {
            if (range != null) {
                result.append(range.toString());
            }
        }
        return result.toString();
    }
}
