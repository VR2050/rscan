package androidx.camera.core.internal.utils;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.BitmapRegionDecoder;
import android.graphics.Rect;
import android.graphics.YuvImage;
import android.util.Rational;
import android.util.Size;
import androidx.annotation.IntRange;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.Logger;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class ImageUtil {
    private static final String TAG = "ImageUtil";

    private ImageUtil() {
    }

    @Nullable
    public static Rect computeCropRectFromAspectRatio(@NonNull Size size, @NonNull Rational rational) {
        int i2;
        if (!isAspectRatioValid(rational)) {
            Logger.m129w(TAG, "Invalid view ratio.");
            return null;
        }
        int width = size.getWidth();
        int height = size.getHeight();
        float f2 = width;
        float f3 = height;
        float f4 = f2 / f3;
        int numerator = rational.getNumerator();
        int denominator = rational.getDenominator();
        int i3 = 0;
        if (rational.floatValue() > f4) {
            int round = Math.round((f2 / numerator) * denominator);
            i2 = (height - round) / 2;
            height = round;
        } else {
            int round2 = Math.round((f3 / denominator) * numerator);
            i3 = (width - round2) / 2;
            width = round2;
            i2 = 0;
        }
        return new Rect(i3, i2, width + i3, height + i2);
    }

    @NonNull
    public static byte[] cropByteArray(@NonNull byte[] bArr, @Nullable Rect rect) {
        if (rect == null) {
            return bArr;
        }
        try {
            BitmapRegionDecoder newInstance = BitmapRegionDecoder.newInstance(bArr, 0, bArr.length, false);
            Bitmap decodeRegion = newInstance.decodeRegion(rect, new BitmapFactory.Options());
            newInstance.recycle();
            if (decodeRegion == null) {
                throw new CodecFailedException("Decode byte array failed.", CodecFailedException.FailureType.DECODE_FAILED);
            }
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            if (!decodeRegion.compress(Bitmap.CompressFormat.JPEG, 100, byteArrayOutputStream)) {
                throw new CodecFailedException("Encode bitmap failed.", CodecFailedException.FailureType.ENCODE_FAILED);
            }
            decodeRegion.recycle();
            return byteArrayOutputStream.toByteArray();
        } catch (IOException unused) {
            throw new CodecFailedException("Decode byte array failed.", CodecFailedException.FailureType.DECODE_FAILED);
        } catch (IllegalArgumentException e2) {
            throw new CodecFailedException("Decode byte array failed with illegal argument." + e2, CodecFailedException.FailureType.DECODE_FAILED);
        }
    }

    @NonNull
    public static Rational getRotatedAspectRatio(@IntRange(from = 0, m111to = 359) int i2, @NonNull Rational rational) {
        return (i2 == 90 || i2 == 270) ? inverseRational(rational) : new Rational(rational.getNumerator(), rational.getDenominator());
    }

    @Nullable
    public static byte[] imageToJpegByteArray(@NonNull ImageProxy imageProxy) {
        if (imageProxy.getFormat() == 256) {
            return jpegImageToJpegByteArray(imageProxy);
        }
        if (imageProxy.getFormat() == 35) {
            return yuvImageToJpegByteArray(imageProxy);
        }
        StringBuilder m586H = C1499a.m586H("Unrecognized image format: ");
        m586H.append(imageProxy.getFormat());
        Logger.m129w(TAG, m586H.toString());
        return null;
    }

    private static Rational inverseRational(Rational rational) {
        return rational == null ? rational : new Rational(rational.getDenominator(), rational.getNumerator());
    }

    public static boolean isAspectRatioValid(@Nullable Rational rational) {
        return (rational == null || rational.floatValue() <= 0.0f || rational.isNaN()) ? false : true;
    }

    private static boolean isCropAspectRatioHasEffect(Size size, Rational rational) {
        int width = size.getWidth();
        int height = size.getHeight();
        float numerator = rational.getNumerator();
        float denominator = rational.getDenominator();
        return (height == Math.round((((float) width) / numerator) * denominator) && width == Math.round((((float) height) / denominator) * numerator)) ? false : true;
    }

    private static byte[] jpegImageToJpegByteArray(ImageProxy imageProxy) {
        ByteBuffer buffer = imageProxy.getPlanes()[0].getBuffer();
        byte[] bArr = new byte[buffer.capacity()];
        buffer.rewind();
        buffer.get(bArr);
        return shouldCropImage(imageProxy) ? cropByteArray(bArr, imageProxy.getCropRect()) : bArr;
    }

    public static float min(float f2, float f3, float f4, float f5) {
        return Math.min(Math.min(f2, f3), Math.min(f4, f5));
    }

    private static byte[] nv21ToJpeg(byte[] bArr, int i2, int i3, @Nullable Rect rect) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        YuvImage yuvImage = new YuvImage(bArr, 17, i2, i3, null);
        if (rect == null) {
            rect = new Rect(0, 0, i2, i3);
        }
        if (yuvImage.compressToJpeg(rect, 100, byteArrayOutputStream)) {
            return byteArrayOutputStream.toByteArray();
        }
        throw new CodecFailedException("YuvImage failed to encode jpeg.", CodecFailedException.FailureType.ENCODE_FAILED);
    }

    private static boolean shouldCropImage(ImageProxy imageProxy) {
        return !new Size(imageProxy.getCropRect().width(), imageProxy.getCropRect().height()).equals(new Size(imageProxy.getWidth(), imageProxy.getHeight()));
    }

    @NonNull
    public static float[] sizeToVertexes(@NonNull Size size) {
        return new float[]{0.0f, 0.0f, size.getWidth(), 0.0f, size.getWidth(), size.getHeight(), 0.0f, size.getHeight()};
    }

    private static byte[] yuvImageToJpegByteArray(ImageProxy imageProxy) {
        return nv21ToJpeg(yuv_420_888toNv21(imageProxy), imageProxy.getWidth(), imageProxy.getHeight(), shouldCropImage(imageProxy) ? imageProxy.getCropRect() : null);
    }

    private static byte[] yuv_420_888toNv21(ImageProxy imageProxy) {
        ImageProxy.PlaneProxy planeProxy = imageProxy.getPlanes()[0];
        ImageProxy.PlaneProxy planeProxy2 = imageProxy.getPlanes()[1];
        ImageProxy.PlaneProxy planeProxy3 = imageProxy.getPlanes()[2];
        ByteBuffer buffer = planeProxy.getBuffer();
        ByteBuffer buffer2 = planeProxy2.getBuffer();
        ByteBuffer buffer3 = planeProxy3.getBuffer();
        buffer.rewind();
        buffer2.rewind();
        buffer3.rewind();
        int remaining = buffer.remaining();
        byte[] bArr = new byte[((imageProxy.getHeight() * imageProxy.getWidth()) / 2) + remaining];
        int i2 = 0;
        for (int i3 = 0; i3 < imageProxy.getHeight(); i3++) {
            buffer.get(bArr, i2, imageProxy.getWidth());
            i2 += imageProxy.getWidth();
            buffer.position(Math.min(remaining, planeProxy.getRowStride() + (buffer.position() - imageProxy.getWidth())));
        }
        int height = imageProxy.getHeight() / 2;
        int width = imageProxy.getWidth() / 2;
        int rowStride = planeProxy3.getRowStride();
        int rowStride2 = planeProxy2.getRowStride();
        int pixelStride = planeProxy3.getPixelStride();
        int pixelStride2 = planeProxy2.getPixelStride();
        byte[] bArr2 = new byte[rowStride];
        byte[] bArr3 = new byte[rowStride2];
        for (int i4 = 0; i4 < height; i4++) {
            buffer3.get(bArr2, 0, Math.min(rowStride, buffer3.remaining()));
            buffer2.get(bArr3, 0, Math.min(rowStride2, buffer2.remaining()));
            int i5 = 0;
            int i6 = 0;
            for (int i7 = 0; i7 < width; i7++) {
                int i8 = i2 + 1;
                bArr[i2] = bArr2[i5];
                i2 = i8 + 1;
                bArr[i8] = bArr3[i6];
                i5 += pixelStride;
                i6 += pixelStride2;
            }
        }
        return bArr;
    }

    public static final class CodecFailedException extends Exception {
        private FailureType mFailureType;

        public enum FailureType {
            ENCODE_FAILED,
            DECODE_FAILED,
            UNKNOWN
        }

        public CodecFailedException(String str) {
            super(str);
            this.mFailureType = FailureType.UNKNOWN;
        }

        @NonNull
        public FailureType getFailureType() {
            return this.mFailureType;
        }

        public CodecFailedException(String str, FailureType failureType) {
            super(str);
            this.mFailureType = failureType;
        }
    }

    public static boolean isAspectRatioValid(@NonNull Size size, @Nullable Rational rational) {
        return rational != null && rational.floatValue() > 0.0f && isCropAspectRatioHasEffect(size, rational) && !rational.isNaN();
    }
}
