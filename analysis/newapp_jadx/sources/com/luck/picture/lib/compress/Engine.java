package com.luck.picture.lib.compress;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;

/* loaded from: classes2.dex */
public class Engine {
    private static final int DEFAULT_QUALITY = 80;
    private int compressQuality;
    private boolean focusAlpha;
    private int srcHeight;
    private InputStreamProvider srcImg;
    private int srcWidth;
    private File tagImg;

    public Engine(InputStreamProvider inputStreamProvider, File file, boolean z, int i2) {
        this.tagImg = file;
        this.srcImg = inputStreamProvider;
        this.focusAlpha = z;
        this.compressQuality = i2 <= 0 ? 80 : i2;
        if (inputStreamProvider.getMedia() != null && inputStreamProvider.getMedia().getWidth() > 0 && inputStreamProvider.getMedia().getHeight() > 0) {
            this.srcWidth = inputStreamProvider.getMedia().getWidth();
            this.srcHeight = inputStreamProvider.getMedia().getHeight();
            return;
        }
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;
        options.inSampleSize = 1;
        BitmapFactory.decodeStream(inputStreamProvider.open(), null, options);
        this.srcWidth = options.outWidth;
        this.srcHeight = options.outHeight;
    }

    private int computeSize() {
        int i2 = this.srcWidth;
        if (i2 % 2 == 1) {
            i2++;
        }
        this.srcWidth = i2;
        int i3 = this.srcHeight;
        if (i3 % 2 == 1) {
            i3++;
        }
        this.srcHeight = i3;
        int max = Math.max(i2, i3);
        float min = Math.min(this.srcWidth, this.srcHeight) / max;
        if (min > 1.0f || min <= 0.5625d) {
            double d2 = min;
            if (d2 > 0.5625d || d2 <= 0.5d) {
                return (int) Math.ceil(max / (1280.0d / d2));
            }
            int i4 = max / 1280;
            if (i4 == 0) {
                return 1;
            }
            return i4;
        }
        if (max < 1664) {
            return 1;
        }
        if (max < 4990) {
            return 2;
        }
        if (max <= 4990 || max >= 10240) {
            return max / 1280;
        }
        return 4;
    }

    private Bitmap rotatingImage(Bitmap bitmap, int i2) {
        Matrix matrix = new Matrix();
        matrix.postRotate(i2);
        return Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), matrix, true);
    }

    public File compress() {
        int orientation;
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inSampleSize = computeSize();
        Bitmap decodeStream = BitmapFactory.decodeStream(this.srcImg.open(), null, options);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        if (this.srcImg.getMedia() != null && !this.srcImg.getMedia().isCut() && Checker.SINGLE.isJPG(this.srcImg.getMedia().getMimeType()) && (orientation = this.srcImg.getMedia().getOrientation()) > 0) {
            boolean z = true;
            if (orientation == 3) {
                orientation = 180;
            } else if (orientation == 6) {
                orientation = 90;
            } else if (orientation != 8) {
                z = false;
            } else {
                orientation = SubsamplingScaleImageView.ORIENTATION_270;
            }
            if (z) {
                decodeStream = rotatingImage(decodeStream, orientation);
            }
        }
        if (decodeStream != null) {
            int i2 = this.compressQuality;
            if (i2 <= 0 || i2 > 100) {
                i2 = 80;
            }
            this.compressQuality = i2;
            decodeStream.compress(this.focusAlpha ? Bitmap.CompressFormat.PNG : Bitmap.CompressFormat.JPEG, i2, byteArrayOutputStream);
            decodeStream.recycle();
        }
        FileOutputStream fileOutputStream = new FileOutputStream(this.tagImg);
        fileOutputStream.write(byteArrayOutputStream.toByteArray());
        fileOutputStream.flush();
        fileOutputStream.close();
        byteArrayOutputStream.close();
        return this.tagImg;
    }
}
