package com.google.android.gms.internal.vision;

import android.graphics.Bitmap;
import android.graphics.Matrix;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes.dex */
public final class zzo {
    public static Bitmap zzb(Bitmap bitmap, zzm zzmVar) {
        int i;
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        if (zzmVar.rotation != 0) {
            Matrix matrix = new Matrix();
            int i2 = zzmVar.rotation;
            if (i2 == 0) {
                i = 0;
            } else if (i2 == 1) {
                i = 90;
            } else if (i2 == 2) {
                i = JavaScreenCapturer.DEGREE_180;
            } else {
                if (i2 != 3) {
                    throw new IllegalArgumentException("Unsupported rotation degree.");
                }
                i = JavaScreenCapturer.DEGREE_270;
            }
            matrix.postRotate(i);
            bitmap = Bitmap.createBitmap(bitmap, 0, 0, width, height, matrix, false);
        }
        if (zzmVar.rotation == 1 || zzmVar.rotation == 3) {
            zzmVar.width = height;
            zzmVar.height = width;
        }
        return bitmap;
    }
}
