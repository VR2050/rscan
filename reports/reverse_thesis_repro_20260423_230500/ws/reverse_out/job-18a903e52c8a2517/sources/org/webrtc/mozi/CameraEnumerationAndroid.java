package org.webrtc.mozi;

import android.graphics.ImageFormat;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import com.king.zxing.util.CodeUtils;
import com.king.zxing.util.LogUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class CameraEnumerationAndroid {
    private static final String TAG = "CameraEnumerationAndroid";
    private static FrameRateDelegate sFrameRateDelegate;
    private static FrameSizeDelegate sFrameSizeDelegate;
    static final ArrayList<Size> COMMON_RESOLUTIONS = new ArrayList<>(Arrays.asList(new Size(160, 120), new Size(PsExtractor.VIDEO_STREAM_MASK, 160), new Size(320, PsExtractor.VIDEO_STREAM_MASK), new Size(400, PsExtractor.VIDEO_STREAM_MASK), new Size(480, 320), new Size(640, 360), new Size(640, 480), new Size(768, 480), new Size(854, 480), new Size(CodeUtils.DEFAULT_REQ_HEIGHT, 600), new Size(960, 540), new Size(960, 640), new Size(1024, 576), new Size(1024, 600), new Size(1280, 720), new Size(1280, 1024), new Size(1920, 1080), new Size(1920, 1440), new Size(2560, 1440), new Size(3840, 2160)));
    public static boolean sFixSelectResolution = true;

    public interface FrameRateDelegate {
        CaptureFormat.FramerateRange getClosestSupportedFramerateRange(List<CaptureFormat.FramerateRange> list, int i);
    }

    public interface FrameSizeDelegate {
        Size getClosestSupportedSize(List<Size> list, int i, int i2);
    }

    public static class CaptureFormat {
        public final FramerateRange framerate;
        public final int height;
        public final int imageFormat = 17;
        public final int width;

        public static class FramerateRange {
            public int max;
            public int min;

            public FramerateRange(int min, int max) {
                this.min = min;
                this.max = max;
            }

            public String toString() {
                return "[" + (this.min / 1000.0f) + LogUtils.COLON + (this.max / 1000.0f) + "]";
            }

            public boolean equals(Object other) {
                if (!(other instanceof FramerateRange)) {
                    return false;
                }
                FramerateRange otherFramerate = (FramerateRange) other;
                return this.min == otherFramerate.min && this.max == otherFramerate.max;
            }

            public int hashCode() {
                return (this.min * 65537) + 1 + this.max;
            }
        }

        public CaptureFormat(int width, int height, int minFramerate, int maxFramerate) {
            this.width = width;
            this.height = height;
            this.framerate = new FramerateRange(minFramerate, maxFramerate);
        }

        public CaptureFormat(int width, int height, FramerateRange framerate) {
            this.width = width;
            this.height = height;
            this.framerate = framerate;
        }

        public int frameSize() {
            return frameSize(this.width, this.height, 17);
        }

        public static int frameSize(int width, int height, int imageFormat) {
            if (imageFormat != 17) {
                throw new UnsupportedOperationException("Don't know how to calculate the frame size of non-NV21 image formats.");
            }
            return ((width * height) * ImageFormat.getBitsPerPixel(imageFormat)) / 8;
        }

        public String toString() {
            return this.width + "x" + this.height + "@" + this.framerate;
        }

        public String toSizeString() {
            return this.width + "x" + this.height;
        }

        public boolean equals(Object other) {
            if (!(other instanceof CaptureFormat)) {
                return false;
            }
            CaptureFormat otherFormat = (CaptureFormat) other;
            return this.width == otherFormat.width && this.height == otherFormat.height && this.framerate.equals(otherFormat.framerate);
        }

        public int hashCode() {
            return (((this.width * 65497) + this.height) * 251) + 1 + this.framerate.hashCode();
        }
    }

    private static abstract class ClosestComparator<T> implements Comparator<T> {
        abstract int diff(T t);

        private ClosestComparator() {
        }

        @Override // java.util.Comparator
        public int compare(T t1, T t2) {
            return diff(t1) - diff(t2);
        }
    }

    public static void setFrameRateDelegate(FrameRateDelegate delegate) {
        sFrameRateDelegate = delegate;
    }

    public static void setFrameSizeDelegate(FrameSizeDelegate delegate) {
        sFrameSizeDelegate = delegate;
    }

    public static CaptureFormat.FramerateRange getClosestSupportedFramerateRange(List<CaptureFormat.FramerateRange> supportedFramerates, final int requestedFps) {
        FrameRateDelegate frameRateDelegate = sFrameRateDelegate;
        if (frameRateDelegate != null) {
            return frameRateDelegate.getClosestSupportedFramerateRange(supportedFramerates, requestedFps);
        }
        return (CaptureFormat.FramerateRange) Collections.min(supportedFramerates, new ClosestComparator<CaptureFormat.FramerateRange>() { // from class: org.webrtc.mozi.CameraEnumerationAndroid.1
            private static final int MAX_FPS_DIFF_THRESHOLD = 5000;
            private static final int MAX_FPS_HIGH_DIFF_WEIGHT = 3;
            private static final int MAX_FPS_LOW_DIFF_WEIGHT = 1;
            private static final int MIN_FPS_HIGH_VALUE_WEIGHT = 4;
            private static final int MIN_FPS_LOW_VALUE_WEIGHT = 1;
            private static final int MIN_FPS_THRESHOLD = 8000;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            private int progressivePenalty(int value, int threshold, int lowWeight, int highWeight) {
                return value < threshold ? value * lowWeight : (threshold * lowWeight) + ((value - threshold) * highWeight);
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.webrtc.mozi.CameraEnumerationAndroid.ClosestComparator
            public int diff(CaptureFormat.FramerateRange range) {
                int minFpsError = progressivePenalty(range.min, 8000, 1, 4);
                int maxFpsError = progressivePenalty(Math.abs((requestedFps * 1000) - range.max), 5000, 1, 3);
                return minFpsError + maxFpsError;
            }
        });
    }

    public static Size getClosestSupportedSize(List<Size> supportedSizes, int requestedWidth, int requestedHeight) {
        int i = requestedWidth;
        int i2 = requestedHeight;
        FrameSizeDelegate frameSizeDelegate = sFrameSizeDelegate;
        if (frameSizeDelegate != null) {
            return frameSizeDelegate.getClosestSupportedSize(supportedSizes, i, i2);
        }
        long closestDistance = Long.MAX_VALUE;
        Size closestSize = null;
        double d = 1.0E8d;
        long requestRatio = (long) ((((double) i) / ((double) i2)) * 1.0E8d);
        long requestDistance = (requestRatio << 32) | ((long) (i << 16)) | ((long) i2);
        for (Size size : supportedSizes) {
            if (size != null && (!sFixSelectResolution || (size.width >= i && size.height >= i2))) {
                long requestDistance2 = requestDistance;
                long curRatio = (long) ((((double) size.width) / ((double) size.height)) * d);
                long curDistance = ((long) (size.width << 16)) | (curRatio << 32) | ((long) size.height);
                long distance = Math.abs(requestDistance2 - curDistance);
                if (distance < closestDistance) {
                    closestDistance = distance;
                    closestSize = size;
                }
                i = requestedWidth;
                i2 = requestedHeight;
                requestDistance = requestDistance2;
                d = 1.0E8d;
            }
        }
        if (closestSize == null) {
            return getClosestSupportedSizeLegacy(supportedSizes, requestedWidth, requestedHeight);
        }
        return closestSize;
    }

    public static Size getClosestSupportedSizeLegacy(List<Size> supportedSizes, final int requestedWidth, final int requestedHeight) {
        return (Size) Collections.min(supportedSizes, new ClosestComparator<Size>() { // from class: org.webrtc.mozi.CameraEnumerationAndroid.2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.webrtc.mozi.CameraEnumerationAndroid.ClosestComparator
            public int diff(Size size) {
                return Math.abs(requestedWidth - size.width) + Math.abs(requestedHeight - size.height);
            }
        });
    }

    static void reportCameraResolution(Histogram histogram, Size resolution) {
        int index = COMMON_RESOLUTIONS.indexOf(resolution);
        histogram.addSample(index + 1);
    }
}
