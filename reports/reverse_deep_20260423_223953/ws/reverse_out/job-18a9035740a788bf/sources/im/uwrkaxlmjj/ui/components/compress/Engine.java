package im.uwrkaxlmjj.ui.components.compress;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/* JADX INFO: loaded from: classes5.dex */
class Engine {
    private boolean focusAlpha;
    private int mCompressQuality;
    private int srcHeight;
    private InputStreamProvider srcImg;
    private int srcWidth;
    private File tagImg;

    Engine(InputStreamProvider srcImg, File tagImg, boolean focusAlpha, int compressQuality) throws IOException {
        this.tagImg = tagImg;
        this.srcImg = srcImg;
        this.focusAlpha = focusAlpha;
        this.mCompressQuality = compressQuality;
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;
        options.inSampleSize = 1;
        BitmapFactory.decodeStream(srcImg.open(), null, options);
        this.srcWidth = options.outWidth;
        this.srcHeight = options.outHeight;
    }

    private int computeSize() {
        int i = this.srcWidth;
        if (i % 2 == 1) {
            i++;
        }
        this.srcWidth = i;
        int i2 = this.srcHeight;
        if (i2 % 2 == 1) {
            i2++;
        }
        this.srcHeight = i2;
        int longSide = Math.max(this.srcWidth, i2);
        int shortSide = Math.min(this.srcWidth, this.srcHeight);
        float scale = shortSide / longSide;
        if (scale > 1.0f || scale <= 0.5625d) {
            if (scale <= 0.5625d && scale > 0.5d) {
                if (longSide / 1280 == 0) {
                    return 1;
                }
                return longSide / 1280;
            }
            return (int) Math.ceil(((double) longSide) / (1280.0d / ((double) scale)));
        }
        if (longSide < 1664) {
            return 1;
        }
        if (longSide < 4990) {
            return 2;
        }
        if (longSide > 4990 && longSide < 10240) {
            return 4;
        }
        if (longSide / 1280 == 0) {
            return 1;
        }
        return longSide / 1280;
    }

    private Bitmap rotatingImage(Bitmap bitmap, int angle) {
        Matrix matrix = new Matrix();
        matrix.postRotate(angle);
        return Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), matrix, true);
    }

    File compress() throws IOException {
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inSampleSize = computeSize();
        Bitmap tagBitmap = BitmapFactory.decodeStream(this.srcImg.open(), null, options);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (Checker.SINGLE.isJPG(this.srcImg.open())) {
            tagBitmap = rotatingImage(tagBitmap, Checker.SINGLE.getOrientation(this.srcImg.open()));
        }
        tagBitmap.compress(this.focusAlpha ? Bitmap.CompressFormat.PNG : Bitmap.CompressFormat.JPEG, this.mCompressQuality, stream);
        tagBitmap.recycle();
        FileOutputStream fos = new FileOutputStream(this.tagImg);
        fos.write(stream.toByteArray());
        fos.flush();
        fos.close();
        stream.close();
        return this.tagImg;
    }
}
