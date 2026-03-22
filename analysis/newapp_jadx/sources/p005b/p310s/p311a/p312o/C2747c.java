package p005b.p310s.p311a.p312o;

import android.graphics.Point;
import android.hardware.Camera;
import android.util.Log;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

/* renamed from: b.s.a.o.c */
/* loaded from: classes2.dex */
public final class C2747c {

    /* renamed from: a */
    public static final /* synthetic */ int f7528a = 0;

    static {
        Pattern.compile(";");
    }

    /* renamed from: a */
    public static Point m3261a(Camera.Parameters parameters, Point point) {
        double d2;
        int i2;
        List<Camera.Size> supportedPreviewSizes = parameters.getSupportedPreviewSizes();
        if (supportedPreviewSizes == null) {
            Camera.Size previewSize = parameters.getPreviewSize();
            if (previewSize != null) {
                return new Point(previewSize.width, previewSize.height);
            }
            throw new IllegalStateException("Parameters contained no preview size!");
        }
        if (Log.isLoggable("CameraConfiguration", 4)) {
            StringBuilder sb = new StringBuilder();
            for (Camera.Size size : supportedPreviewSizes) {
                sb.append(size.width);
                sb.append('x');
                sb.append(size.height);
                sb.append(' ');
            }
            String str = "Supported preview sizes: " + ((Object) sb);
        }
        int i3 = point.x;
        int i4 = point.y;
        double d3 = i3 < i4 ? i3 / i4 : i4 / i3;
        Camera.Size size2 = null;
        char c2 = 0;
        int i5 = 0;
        for (Camera.Size size3 : supportedPreviewSizes) {
            int i6 = size3.width;
            int i7 = size3.height;
            int i8 = i6 * i7;
            if (i8 < 153600) {
                d2 = d3;
                i2 = i5;
            } else {
                boolean z = i6 < i7;
                int i9 = z ? i6 : i7;
                int i10 = z ? i7 : i6;
                Object[] objArr = new Object[2];
                objArr[c2] = Integer.valueOf(i9);
                objArr[1] = Integer.valueOf(i10);
                String.format("maybeFlipped:%d * %d", objArr);
                d2 = d3;
                i2 = i5;
                if (Math.abs((i9 / i10) - d2) <= 0.05d) {
                    if (i9 == point.x && i10 == point.y) {
                        Point point2 = new Point(i6, i7);
                        String str2 = "Found preview size exactly matching screen size: " + point2;
                        return point2;
                    }
                    if (i8 > i2) {
                        size2 = size3;
                        i5 = i8;
                        d3 = d2;
                        c2 = 0;
                    }
                }
            }
            i5 = i2;
            d3 = d2;
            c2 = 0;
        }
        if (size2 != null) {
            Point point3 = new Point(size2.width, size2.height);
            String str3 = "Using largest suitable preview size: " + point3;
            return point3;
        }
        Camera.Size previewSize2 = parameters.getPreviewSize();
        if (previewSize2 == null) {
            throw new IllegalStateException("Parameters contained no preview size!");
        }
        Point point4 = new Point(previewSize2.width, previewSize2.height);
        String str4 = "No suitable preview sizes, using default: " + point4;
        return point4;
    }

    /* renamed from: b */
    public static String m3262b(String str, Collection<String> collection, String... strArr) {
        Arrays.toString(strArr);
        String str2 = "Supported " + str + " values: " + collection;
        if (collection == null) {
            return null;
        }
        for (String str3 : strArr) {
            if (collection.contains(str3)) {
                return str3;
            }
        }
        return null;
    }

    /* renamed from: c */
    public static String m3263c(Iterable<Camera.Area> iterable) {
        if (iterable == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (Camera.Area area : iterable) {
            sb.append(area.rect);
            sb.append(':');
            sb.append(area.weight);
            sb.append(' ');
        }
        return sb.toString();
    }
}
