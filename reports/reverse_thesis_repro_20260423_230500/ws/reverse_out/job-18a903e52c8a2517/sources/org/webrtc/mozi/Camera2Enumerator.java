package org.webrtc.mozi;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.os.Build;
import android.os.SystemClock;
import android.util.AndroidException;
import android.util.Range;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.webrtc.mozi.CameraEnumerationAndroid;
import org.webrtc.mozi.CameraVideoCapturer;

/* JADX INFO: loaded from: classes3.dex */
public class Camera2Enumerator implements CameraEnumerator {
    private static final double NANO_SECONDS_PER_SECOND = 1.0E9d;
    private static final String TAG = "Camera2Enumerator";
    private static final Map<String, List<CameraEnumerationAndroid.CaptureFormat>> cachedSupportedFormats = new HashMap();

    @Nullable
    final CameraManager cameraManager;
    final Context context;
    private final boolean fixCamera2LogicalDevice;

    public Camera2Enumerator(Context context) {
        this(context, false);
    }

    public Camera2Enumerator(Context context, boolean fixCamera2LogicalDevice) {
        this.context = context;
        this.cameraManager = (CameraManager) context.getSystemService("camera");
        this.fixCamera2LogicalDevice = fixCamera2LogicalDevice;
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public String[] getDeviceNames() {
        try {
            if (this.fixCamera2LogicalDevice) {
                String[] deviceNames = this.cameraManager.getCameraIdList();
                Logging.d(TAG, "cameraNames: " + Arrays.toString(deviceNames));
                String[] filterSupportedLogicalDevices = filterSupportedLogicalDevices(this.cameraManager, deviceNames);
                Logging.d(TAG, "filtered cameraNames: " + Arrays.toString(filterSupportedLogicalDevices));
                return filterSupportedLogicalDevices;
            }
            return this.cameraManager.getCameraIdList();
        } catch (AndroidException e) {
            Logging.e(TAG, "Camera access exception: " + e);
            return new String[0];
        }
    }

    public static String[] filterSupportedLogicalDevices(CameraManager cameraManager, String[] cameraIds) throws CameraAccessException {
        if (cameraManager == null || cameraIds == null) {
            return cameraIds;
        }
        String firstFront = null;
        String firstBack = null;
        List<String> externals = new ArrayList<>();
        for (String cameraId : cameraIds) {
            CameraCharacteristics cameraCharacteristics = null;
            try {
                cameraCharacteristics = cameraManager.getCameraCharacteristics(cameraId);
            } catch (Exception e) {
                Logging.d(TAG, "isCamera2DeviceSupported: getChara fail, " + e.getMessage());
                e.printStackTrace();
            }
            if (cameraCharacteristics != null) {
                Integer facing = (Integer) cameraCharacteristics.get(CameraCharacteristics.LENS_FACING);
                if (facing.intValue() == 2) {
                    externals.add(cameraId);
                } else if (firstFront == null && facing.intValue() == 0) {
                    firstFront = cameraId;
                } else if (firstBack == null && facing.intValue() == 1) {
                    firstBack = cameraId;
                }
            }
        }
        List<String> supportedCameraIds = new ArrayList<>(externals);
        if (firstFront != null) {
            supportedCameraIds.add(firstFront);
        }
        if (firstBack != null) {
            supportedCameraIds.add(firstBack);
        }
        return (String[]) supportedCameraIds.toArray(new String[0]);
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public boolean isFrontFacing(String deviceName) {
        CameraCharacteristics characteristics = getCameraCharacteristics(deviceName);
        return characteristics != null && ((Integer) characteristics.get(CameraCharacteristics.LENS_FACING)).intValue() == 0;
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public boolean isBackFacing(String deviceName) {
        CameraCharacteristics characteristics = getCameraCharacteristics(deviceName);
        return characteristics != null && ((Integer) characteristics.get(CameraCharacteristics.LENS_FACING)).intValue() == 1;
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public List<CameraEnumerationAndroid.CaptureFormat> getSupportedFormats(String deviceName) {
        return getSupportedFormats(this.context, deviceName);
    }

    @Override // org.webrtc.mozi.CameraEnumerator
    public CameraVideoCapturer createCapturer(String deviceName, CameraVideoCapturer.CameraEventsHandler eventsHandler) {
        return new Camera2Capturer(this.context, deviceName, eventsHandler);
    }

    @Nullable
    private CameraCharacteristics getCameraCharacteristics(String deviceName) {
        try {
            return this.cameraManager.getCameraCharacteristics(deviceName);
        } catch (AndroidException e) {
            Logging.e(TAG, "Camera access exception: " + e);
            return null;
        }
    }

    public static boolean isSupported(Context context) {
        if (Build.VERSION.SDK_INT < 21) {
            return false;
        }
        CameraManager cameraManager = (CameraManager) context.getSystemService("camera");
        try {
            String[] cameraIds = cameraManager.getCameraIdList();
            for (String id : cameraIds) {
                CameraCharacteristics characteristics = cameraManager.getCameraCharacteristics(id);
                if (((Integer) characteristics.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL)).intValue() == 2) {
                    return false;
                }
            }
            return true;
        } catch (AndroidException e) {
            Logging.e(TAG, "Camera access exception: " + e);
            return false;
        }
    }

    static int getFpsUnitFactor(Range<Integer>[] fpsRanges) {
        return (fpsRanges.length != 0 && ((Integer) fpsRanges[0].getUpper()).intValue() >= 1000) ? 1 : 1000;
    }

    static List<Size> getSupportedSizes(CameraCharacteristics cameraCharacteristics) {
        StreamConfigurationMap streamMap = (StreamConfigurationMap) cameraCharacteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
        int supportLevel = ((Integer) cameraCharacteristics.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL)).intValue();
        android.util.Size[] nativeSizes = streamMap.getOutputSizes(SurfaceTexture.class);
        List<Size> sizes = convertSizes(nativeSizes);
        if (Build.VERSION.SDK_INT < 22 && supportLevel == 2) {
            Rect activeArraySize = (Rect) cameraCharacteristics.get(CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE);
            ArrayList<Size> filteredSizes = new ArrayList<>();
            for (Size size : sizes) {
                if (activeArraySize.width() * size.height == activeArraySize.height() * size.width) {
                    filteredSizes.add(size);
                }
            }
            return filteredSizes;
        }
        return sizes;
    }

    static List<CameraEnumerationAndroid.CaptureFormat> getSupportedFormats(Context context, String cameraId) {
        return getSupportedFormats((CameraManager) context.getSystemService("camera"), cameraId);
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 4 */
    static List<CameraEnumerationAndroid.CaptureFormat> getSupportedFormats(CameraManager cameraManager, String cameraId) throws CameraAccessException {
        Range<Integer>[] fpsRanges;
        List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> framerateRanges;
        StreamConfigurationMap streamMap;
        int maxFps;
        synchronized (cachedSupportedFormats) {
            if (cachedSupportedFormats.containsKey(cameraId)) {
                return cachedSupportedFormats.get(cameraId);
            }
            Logging.d(TAG, "Get supported formats for camera index " + cameraId + ".");
            long startTimeMs = SystemClock.elapsedRealtime();
            try {
                CameraCharacteristics cameraCharacteristics = cameraManager.getCameraCharacteristics(cameraId);
                StreamConfigurationMap streamMap2 = (StreamConfigurationMap) cameraCharacteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
                Range<Integer>[] fpsRanges2 = (Range[]) cameraCharacteristics.get(CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES);
                List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> framerateRanges2 = convertFramerates(fpsRanges2, getFpsUnitFactor(fpsRanges2));
                List<Size> sizes = getSupportedSizes(cameraCharacteristics);
                int defaultMaxFps = 0;
                for (CameraEnumerationAndroid.CaptureFormat.FramerateRange framerateRange : framerateRanges2) {
                    defaultMaxFps = Math.max(defaultMaxFps, framerateRange.max);
                }
                List<CameraEnumerationAndroid.CaptureFormat> formatList = new ArrayList<>();
                for (Size size : sizes) {
                    long minFrameDurationNs = 0;
                    CameraCharacteristics cameraCharacteristics2 = cameraCharacteristics;
                    try {
                        fpsRanges = fpsRanges2;
                        try {
                            framerateRanges = framerateRanges2;
                            try {
                                minFrameDurationNs = streamMap2.getOutputMinFrameDuration(SurfaceTexture.class, new android.util.Size(size.width, size.height));
                            } catch (Exception e) {
                            }
                        } catch (Exception e2) {
                            framerateRanges = framerateRanges2;
                        }
                    } catch (Exception e3) {
                        fpsRanges = fpsRanges2;
                        framerateRanges = framerateRanges2;
                    }
                    if (minFrameDurationNs == 0) {
                        streamMap = streamMap2;
                        maxFps = defaultMaxFps;
                    } else {
                        streamMap = streamMap2;
                        maxFps = ((int) Math.round(NANO_SECONDS_PER_SECOND / minFrameDurationNs)) * 1000;
                    }
                    formatList.add(new CameraEnumerationAndroid.CaptureFormat(size.width, size.height, 0, maxFps));
                    Logging.d(TAG, "Format: " + size.width + "x" + size.height + "@" + maxFps);
                    cameraCharacteristics = cameraCharacteristics2;
                    fpsRanges2 = fpsRanges;
                    framerateRanges2 = framerateRanges;
                    streamMap2 = streamMap;
                }
                cachedSupportedFormats.put(cameraId, formatList);
                long endTimeMs = SystemClock.elapsedRealtime();
                Logging.d(TAG, "Get supported formats for camera index " + cameraId + " done. Time spent: " + (endTimeMs - startTimeMs) + " ms.");
                return formatList;
            } catch (Exception ex) {
                Logging.e(TAG, "getCameraCharacteristics(): " + ex);
                return new ArrayList();
            }
        }
    }

    private static List<Size> convertSizes(android.util.Size[] cameraSizes) {
        List<Size> sizes = new ArrayList<>();
        for (android.util.Size size : cameraSizes) {
            sizes.add(new Size(size.getWidth(), size.getHeight()));
        }
        return sizes;
    }

    static List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> convertFramerates(Range<Integer>[] arrayRanges, int unitFactor) {
        List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> ranges = new ArrayList<>();
        for (Range<Integer> range : arrayRanges) {
            ranges.add(new CameraEnumerationAndroid.CaptureFormat.FramerateRange(((Integer) range.getLower()).intValue() * unitFactor, ((Integer) range.getUpper()).intValue() * unitFactor));
        }
        return ranges;
    }
}
