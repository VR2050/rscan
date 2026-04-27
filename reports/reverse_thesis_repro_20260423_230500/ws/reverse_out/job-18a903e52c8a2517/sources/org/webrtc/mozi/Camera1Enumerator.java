package org.webrtc.mozi;

import android.hardware.Camera;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;
import org.webrtc.mozi.CameraEnumerationAndroid;
import org.webrtc.mozi.CameraVideoCapturer;

/* JADX INFO: loaded from: classes3.dex */
public class Camera1Enumerator implements CameraEnumerator {
    private static final String TAG = "Camera1Enumerator";
    private static List<List<CameraEnumerationAndroid.CaptureFormat>> cachedSupportedFormats;
    private static boolean sFixGetCameraNumberAnr = true;
    private static int sNumberOfCameras = 0;
    private final boolean captureToTexture;

    public Camera1Enumerator() {
        this(true);
    }

    public Camera1Enumerator(boolean captureToTexture) {
        this.captureToTexture = captureToTexture;
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public String[] getDeviceNames() {
        ArrayList<String> namesList = new ArrayList<>();
        int cameraNumber = getNumberOfCameras();
        for (int i = 0; i < cameraNumber; i++) {
            String name = getDeviceName(i);
            if (name != null) {
                namesList.add(name);
                Logging.d(TAG, "Index: " + i + ". " + name);
            } else {
                Logging.e(TAG, "Index: " + i + ". Failed to query camera name.");
            }
        }
        int i2 = namesList.size();
        String[] namesArray = new String[i2];
        return (String[]) namesList.toArray(namesArray);
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public boolean isFrontFacing(String deviceName) {
        Camera.CameraInfo info = getCameraInfo(getCameraIndex(deviceName));
        return info != null && info.facing == 1;
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public boolean isBackFacing(String deviceName) {
        Camera.CameraInfo info = getCameraInfo(getCameraIndex(deviceName));
        return info != null && info.facing == 0;
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public List<CameraEnumerationAndroid.CaptureFormat> getSupportedFormats(String deviceName) {
        return getSupportedFormats(getCameraIndex(deviceName));
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public CameraVideoCapturer createCapturer(String deviceName, CameraVideoCapturer.CameraEventsHandler eventsHandler) {
        return new Camera1Capturer(deviceName, true, eventsHandler, this.captureToTexture, null);
    }

    @Nullable
    private static Camera.CameraInfo getCameraInfo(int index) {
        Camera.CameraInfo info = new Camera.CameraInfo();
        try {
            Camera.getCameraInfo(index, info);
            return info;
        } catch (Exception e) {
            Logging.e(TAG, "getCameraInfo failed on index " + index, e);
            return null;
        }
    }

    static synchronized List<CameraEnumerationAndroid.CaptureFormat> getSupportedFormats(int cameraId) {
        if (cachedSupportedFormats == null) {
            cachedSupportedFormats = new ArrayList();
            int cameraNumber = getNumberOfCameras();
            for (int i = 0; i < cameraNumber; i++) {
                cachedSupportedFormats.add(enumerateFormats(i));
            }
        }
        return cachedSupportedFormats.get(cameraId);
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00ed  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static java.util.List<org.webrtc.mozi.CameraEnumerationAndroid.CaptureFormat> enumerateFormats(int r15) {
        /*
            Method dump skipped, instruction units count: 241
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.Camera1Enumerator.enumerateFormats(int):java.util.List");
    }

    static List<Size> convertSizes(List<Camera.Size> cameraSizes) {
        List<Size> sizes = new ArrayList<>();
        for (Camera.Size size : cameraSizes) {
            sizes.add(new Size(size.width, size.height));
        }
        return sizes;
    }

    static List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> convertFramerates(List<int[]> arrayRanges) {
        List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> ranges = new ArrayList<>();
        for (int[] range : arrayRanges) {
            ranges.add(new CameraEnumerationAndroid.CaptureFormat.FramerateRange(range[0], range[1]));
        }
        return ranges;
    }

    static int getCameraIndex(String deviceName) {
        Logging.d(TAG, "getCameraIndex: " + deviceName);
        int cameraNumber = getNumberOfCameras();
        for (int i = 0; i < cameraNumber; i++) {
            if (deviceName.equals(getDeviceName(i))) {
                return i;
            }
        }
        throw new IllegalArgumentException("No such camera: " + deviceName);
    }

    @Nullable
    static String getDeviceName(int index) {
        Camera.CameraInfo info = getCameraInfo(index);
        if (info == null) {
            return null;
        }
        String facing = info.facing == 1 ? "front" : "back";
        return "Camera " + index + ", Facing " + facing + ", Orientation " + info.orientation;
    }

    public static void setFixGetCameraNumberAnr(boolean fixGetCameraNumberAnr) {
        sFixGetCameraNumberAnr = fixGetCameraNumberAnr;
    }

    private static int getNumberOfCameras() {
        if (sFixGetCameraNumberAnr) {
            if (sNumberOfCameras <= 0) {
                sNumberOfCameras = Camera.getNumberOfCameras();
            }
            return sNumberOfCameras;
        }
        return Camera.getNumberOfCameras();
    }
}
