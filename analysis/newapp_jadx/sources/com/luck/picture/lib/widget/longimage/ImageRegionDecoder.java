package com.luck.picture.lib.widget.longimage;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Point;
import android.graphics.Rect;
import android.net.Uri;

/* loaded from: classes2.dex */
public interface ImageRegionDecoder {
    Bitmap decodeRegion(Rect rect, int i2);

    Point init(Context context, Uri uri);

    boolean isReady();

    void recycle();
}
