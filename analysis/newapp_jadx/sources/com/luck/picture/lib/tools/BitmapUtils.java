package com.luck.picture.lib.tools;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;

/* loaded from: classes2.dex */
public class BitmapUtils {
    public static int getRotationAngle(int i2) {
        if (i2 == 3) {
            return 180;
        }
        if (i2 == 6) {
            return 90;
        }
        if (i2 != 8) {
            return 0;
        }
        return SubsamplingScaleImageView.ORIENTATION_270;
    }

    public static void rotateImage(int i2, String str) {
        if (i2 > 0) {
            try {
                BitmapFactory.Options options = new BitmapFactory.Options();
                options.inSampleSize = 2;
                File file = new File(str);
                Bitmap rotatingImage = rotatingImage(BitmapFactory.decodeFile(file.getAbsolutePath(), options), i2);
                if (rotatingImage != null) {
                    saveBitmapFile(rotatingImage, file);
                    rotatingImage.recycle();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    public static Bitmap rotatingImage(Bitmap bitmap, int i2) {
        Matrix matrix = new Matrix();
        matrix.postRotate(i2);
        return Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), matrix, true);
    }

    public static void saveBitmapFile(Bitmap bitmap, File file) {
        try {
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file));
            bitmap.compress(Bitmap.CompressFormat.JPEG, 100, bufferedOutputStream);
            bufferedOutputStream.flush();
            bufferedOutputStream.close();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }
}
