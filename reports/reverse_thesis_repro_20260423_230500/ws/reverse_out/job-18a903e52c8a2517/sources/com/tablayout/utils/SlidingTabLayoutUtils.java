package com.tablayout.utils;

import android.graphics.Bitmap;
import android.view.View;

/* JADX INFO: loaded from: classes2.dex */
public class SlidingTabLayoutUtils {
    public static Bitmap generateViewCacheBitmap(View view) {
        view.destroyDrawingCache();
        int widthMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        int heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        view.measure(widthMeasureSpec, heightMeasureSpec);
        int width = view.getMeasuredWidth();
        int height = view.getMeasuredHeight();
        view.layout(0, 0, width, height);
        view.setDrawingCacheEnabled(true);
        view.buildDrawingCache();
        return Bitmap.createBitmap(view.getDrawingCache());
    }

    public static View findBrotherView(View view, int id, int level) {
        int count = 0;
        View temp = view;
        while (count < level) {
            View target = temp.findViewById(id);
            if (target != null) {
                return target;
            }
            count++;
            if (temp.getParent() instanceof View) {
                temp = (View) temp.getParent();
            } else {
                return null;
            }
        }
        return null;
    }
}
