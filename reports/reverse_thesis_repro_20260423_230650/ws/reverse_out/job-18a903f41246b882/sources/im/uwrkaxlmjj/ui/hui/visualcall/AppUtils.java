package im.uwrkaxlmjj.ui.hui.visualcall;

import android.app.ActivityManager;
import android.content.Context;
import android.graphics.Bitmap;
import android.os.Build;
import android.renderscript.Allocation;
import android.renderscript.RenderScript;
import android.renderscript.ScriptIntrinsicBlur;
import android.text.TextUtils;
import androidx.core.view.MotionEventCompat;
import java.lang.reflect.Array;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class AppUtils {
    private static final int VALUE = 100;

    public static boolean isServiceRunning(Context context, String serviceName) {
        if (TextUtils.isEmpty(serviceName)) {
            return false;
        }
        ActivityManager am = (ActivityManager) context.getSystemService("activity");
        List<ActivityManager.RunningServiceInfo> runningServiceInfos = am.getRunningServices(100);
        if (runningServiceInfos.size() <= 0) {
            return false;
        }
        for (ActivityManager.RunningServiceInfo serviceInfo : runningServiceInfos) {
            if (serviceInfo.service.getClassName().equals(serviceName)) {
                return true;
            }
        }
        return false;
    }

    public static Bitmap blur(Bitmap bitmap, float radius, Context context) {
        Bitmap bitmap2 = Bitmap.createScaledBitmap(bitmap, bitmap.getWidth() / 1, bitmap.getHeight() / 1, false);
        if (Build.VERSION.SDK_INT >= 17) {
            RenderScript rs = RenderScript.create(context);
            Allocation allocFromBmp = Allocation.createFromBitmap(rs, bitmap2);
            ScriptIntrinsicBlur blur = ScriptIntrinsicBlur.create(rs, allocFromBmp.getElement());
            blur.setInput(allocFromBmp);
            blur.setRadius(radius);
            blur.forEach(allocFromBmp);
            allocFromBmp.copyTo(bitmap2);
            rs.destroy();
        }
        return bitmap2;
    }

    public static Bitmap doBlur(Bitmap sentBitmap, int radius, boolean canReuseInBitmap) {
        Bitmap bitmap;
        int i;
        int i2;
        int p = radius;
        if (canReuseInBitmap) {
            bitmap = sentBitmap;
        } else {
            bitmap = sentBitmap.copy(sentBitmap.getConfig(), true);
        }
        if (p < 1) {
            return null;
        }
        int w = bitmap.getWidth();
        int rbs = bitmap.getHeight();
        int[] pix = new int[w * rbs];
        bitmap.getPixels(pix, 0, w, 0, 0, w, rbs);
        int wm = w - 1;
        int p2 = rbs - 1;
        int bsum = w * rbs;
        int div = p + p + 1;
        int[] r = new int[bsum];
        int[] g = new int[bsum];
        int[] b = new int[bsum];
        int[] vmin = new int[Math.max(w, rbs)];
        int divsum = (div + 1) >> 1;
        int divsum2 = divsum * divsum;
        int[] dv = new int[divsum2 * 256];
        for (int i3 = 0; i3 < divsum2 * 256; i3++) {
            dv[i3] = i3 / divsum2;
        }
        int yi = 0;
        int yw = 0;
        int[][] stack = (int[][]) Array.newInstance((Class<?>) int.class, div, 3);
        int r1 = p + 1;
        int divsum3 = 0;
        while (divsum3 < rbs) {
            int rsum = 0;
            int boutsum = 0;
            int goutsum = 0;
            int routsum = 0;
            int binsum = 0;
            int ginsum = 0;
            int rinsum = 0;
            int wh = bsum;
            int wh2 = -p;
            int i4 = 0;
            Bitmap bitmap2 = bitmap;
            int p3 = wh2;
            int bsum2 = 0;
            while (p3 <= p) {
                int hm = p2;
                int h = rbs;
                int hm2 = Math.max(p3, 0);
                int p4 = pix[yi + Math.min(wm, hm2)];
                int[] sir = stack[p3 + p];
                sir[0] = (p4 & 16711680) >> 16;
                sir[1] = (p4 & MotionEventCompat.ACTION_POINTER_INDEX_MASK) >> 8;
                sir[2] = p4 & 255;
                int rbs2 = r1 - Math.abs(p3);
                rsum += sir[0] * rbs2;
                i4 += sir[1] * rbs2;
                bsum2 += sir[2] * rbs2;
                if (p3 > 0) {
                    rinsum += sir[0];
                    ginsum += sir[1];
                    binsum += sir[2];
                } else {
                    routsum += sir[0];
                    goutsum += sir[1];
                    boutsum += sir[2];
                }
                p3++;
                p2 = hm;
                rbs = h;
            }
            int hm3 = p2;
            int h2 = rbs;
            int stackpointer = radius;
            int x = 0;
            while (x < w) {
                r[yi] = dv[rsum];
                g[yi] = dv[i4];
                b[yi] = dv[bsum2];
                int rsum2 = rsum - routsum;
                int gsum = i4 - goutsum;
                int bsum3 = bsum2 - boutsum;
                int stackstart = (stackpointer - p) + div;
                int[] sir2 = stack[stackstart % div];
                int routsum2 = routsum - sir2[0];
                int goutsum2 = goutsum - sir2[1];
                int boutsum2 = boutsum - sir2[2];
                if (divsum3 != 0) {
                    i2 = p3;
                } else {
                    i2 = p3;
                    int i5 = x + p + 1;
                    vmin[x] = Math.min(i5, wm);
                }
                int i6 = vmin[x];
                int p5 = pix[yw + i6];
                sir2[0] = (p5 & 16711680) >> 16;
                sir2[1] = (p5 & MotionEventCompat.ACTION_POINTER_INDEX_MASK) >> 8;
                int wm2 = wm;
                int wm3 = p5 & 255;
                sir2[2] = wm3;
                int rinsum2 = rinsum + sir2[0];
                int ginsum2 = ginsum + sir2[1];
                int binsum2 = binsum + sir2[2];
                rsum = rsum2 + rinsum2;
                i4 = gsum + ginsum2;
                bsum2 = bsum3 + binsum2;
                stackpointer = (stackpointer + 1) % div;
                int[] sir3 = stack[stackpointer % div];
                routsum = routsum2 + sir3[0];
                goutsum = goutsum2 + sir3[1];
                boutsum = boutsum2 + sir3[2];
                rinsum = rinsum2 - sir3[0];
                ginsum = ginsum2 - sir3[1];
                binsum = binsum2 - sir3[2];
                yi++;
                x++;
                wm = wm2;
                p3 = i2;
            }
            yw += w;
            divsum3++;
            p2 = hm3;
            bitmap = bitmap2;
            bsum = wh;
            rbs = h2;
        }
        Bitmap bitmap3 = bitmap;
        int hm4 = p2;
        int h3 = rbs;
        int x2 = 0;
        int h4 = divsum3;
        while (x2 < w) {
            int bsum4 = 0;
            int gsum2 = 0;
            int rsum3 = 0;
            int yp = (-p) * w;
            int yp2 = -p;
            int i7 = 0;
            int y = yp2;
            int yp3 = yp;
            int rinsum3 = 0;
            int ginsum3 = 0;
            int binsum3 = 0;
            int binsum4 = 0;
            int routsum3 = 0;
            while (y <= p) {
                int[] vmin2 = vmin;
                int yi2 = Math.max(0, yp3) + x2;
                int[] sir4 = stack[y + p];
                sir4[0] = r[yi2];
                sir4[1] = g[yi2];
                sir4[2] = b[yi2];
                int rbs3 = r1 - Math.abs(y);
                rsum3 += r[yi2] * rbs3;
                gsum2 += g[yi2] * rbs3;
                bsum4 += b[yi2] * rbs3;
                if (y > 0) {
                    rinsum3 += sir4[0];
                    ginsum3 += sir4[1];
                    binsum3 += sir4[2];
                } else {
                    binsum4 += sir4[0];
                    routsum3 += sir4[1];
                    i7 += sir4[2];
                }
                int rbs4 = hm4;
                if (y < rbs4) {
                    yp3 += w;
                }
                y++;
                hm4 = rbs4;
                vmin = vmin2;
            }
            int[] vmin3 = vmin;
            int hm5 = hm4;
            int yi3 = x2;
            int yi4 = rsum3;
            int rsum4 = 0;
            int stackpointer2 = radius;
            int stackpointer3 = i7;
            int boutsum3 = yi3;
            while (true) {
                int i8 = y;
                i = h3;
                if (rsum4 < i) {
                    pix[boutsum3] = (pix[boutsum3] & (-16777216)) | (dv[yi4] << 16) | (dv[gsum2] << 8) | dv[bsum4];
                    int rsum5 = yi4 - binsum4;
                    int gsum3 = gsum2 - routsum3;
                    int bsum5 = bsum4 - stackpointer3;
                    int stackstart2 = (stackpointer2 - p) + div;
                    int[] sir5 = stack[stackstart2 % div];
                    int routsum4 = binsum4 - sir5[0];
                    int goutsum3 = routsum3 - sir5[1];
                    int boutsum4 = stackpointer3 - sir5[2];
                    if (x2 == 0) {
                        vmin3[rsum4] = Math.min(rsum4 + r1, hm5) * w;
                    }
                    int p6 = vmin3[rsum4] + x2;
                    sir5[0] = r[p6];
                    sir5[1] = g[p6];
                    sir5[2] = b[p6];
                    int rinsum4 = rinsum3 + sir5[0];
                    int ginsum4 = ginsum3 + sir5[1];
                    int binsum5 = binsum3 + sir5[2];
                    yi4 = rsum5 + rinsum4;
                    gsum2 = gsum3 + ginsum4;
                    bsum4 = bsum5 + binsum5;
                    stackpointer2 = (stackpointer2 + 1) % div;
                    int[] sir6 = stack[stackpointer2];
                    binsum4 = routsum4 + sir6[0];
                    routsum3 = goutsum3 + sir6[1];
                    stackpointer3 = boutsum4 + sir6[2];
                    rinsum3 = rinsum4 - sir6[0];
                    ginsum3 = ginsum4 - sir6[1];
                    binsum3 = binsum5 - sir6[2];
                    boutsum3 += w;
                    rsum4++;
                    p = radius;
                    h3 = i;
                    y = i8;
                }
            }
            x2++;
            p = radius;
            hm4 = hm5;
            h3 = i;
            h4 = rsum4;
            vmin = vmin3;
        }
        int y2 = h3;
        bitmap3.setPixels(pix, 0, w, 0, 0, w, y2);
        return bitmap3;
    }
}
