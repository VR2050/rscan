package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class JavaCameraEnumerator {
    private static final String TAG = "JavaCameraEnumerator";
    private String[] mDeviceNames;
    private CameraEnumerator mEnumerator;
    private long mNativeHandler;

    public JavaCameraEnumerator(long nativeHandler) {
        this.mNativeHandler = 0L;
        this.mDeviceNames = null;
        Logging.d(TAG, "JavaCameraEnumerator " + nativeHandler);
        this.mNativeHandler = nativeHandler;
        Camera1Enumerator camera1Enumerator = new Camera1Enumerator(true);
        this.mEnumerator = camera1Enumerator;
        this.mDeviceNames = camera1Enumerator.getDeviceNames();
    }

    public void dispose() {
        Logging.d(TAG, "dispose");
        if (this.mEnumerator != null) {
            this.mEnumerator = null;
        }
    }

    public int numberOfDevices() {
        String[] strArr = this.mDeviceNames;
        if (strArr != null) {
            return strArr.length;
        }
        return 0;
    }

    public String getDeviceName(int deviceNumber) {
        String[] strArr = this.mDeviceNames;
        if (strArr == null || strArr.length <= deviceNumber) {
            return null;
        }
        return strArr[deviceNumber];
    }
}
