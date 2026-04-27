package com.google.android.gms.vision.text;

import android.graphics.Point;
import android.graphics.Rect;
import com.google.android.gms.internal.vision.zzr;

/* JADX INFO: loaded from: classes.dex */
final class zzc {
    static Rect zza(Text text) {
        int iMax = Integer.MIN_VALUE;
        int iMax2 = Integer.MIN_VALUE;
        int iMin = Integer.MAX_VALUE;
        int iMin2 = Integer.MAX_VALUE;
        for (Point point : text.getCornerPoints()) {
            iMin = Math.min(iMin, point.x);
            iMax = Math.max(iMax, point.x);
            iMin2 = Math.min(iMin2, point.y);
            iMax2 = Math.max(iMax2, point.y);
        }
        return new Rect(iMin, iMin2, iMax, iMax2);
    }

    static Point[] zza(zzr zzrVar) {
        Point[] pointArr = new Point[4];
        double dSin = Math.sin(Math.toRadians(zzrVar.zzdh));
        double dCos = Math.cos(Math.toRadians(zzrVar.zzdh));
        pointArr[0] = new Point(zzrVar.left, zzrVar.top);
        pointArr[1] = new Point((int) (((double) zzrVar.left) + (((double) zzrVar.width) * dCos)), (int) (((double) zzrVar.top) + (((double) zzrVar.width) * dSin)));
        pointArr[2] = new Point((int) (((double) pointArr[1].x) - (((double) zzrVar.height) * dSin)), (int) (((double) pointArr[1].y) + (((double) zzrVar.height) * dCos)));
        pointArr[3] = new Point(pointArr[0].x + (pointArr[2].x - pointArr[1].x), pointArr[0].y + (pointArr[2].y - pointArr[1].y));
        return pointArr;
    }
}
