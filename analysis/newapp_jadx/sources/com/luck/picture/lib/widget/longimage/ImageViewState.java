package com.luck.picture.lib.widget.longimage;

import android.graphics.PointF;
import java.io.Serializable;

/* loaded from: classes2.dex */
public class ImageViewState implements Serializable {
    private float centerX;
    private float centerY;
    private int orientation;
    private float scale;

    public ImageViewState(float f2, PointF pointF, int i2) {
        this.scale = f2;
        this.centerX = pointF.x;
        this.centerY = pointF.y;
        this.orientation = i2;
    }

    public PointF getCenter() {
        return new PointF(this.centerX, this.centerY);
    }

    public int getOrientation() {
        return this.orientation;
    }

    public float getScale() {
        return this.scale;
    }
}
