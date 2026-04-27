package com.scwang.smartrefresh.layout.internal;

import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;

/* JADX INFO: loaded from: classes3.dex */
public class ArrowDrawable extends PaintDrawable {
    private int mWidth = 0;
    private int mHeight = 0;
    private Path mPath = new Path();

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Rect bounds = getBounds();
        int width = bounds.width();
        int height = bounds.height();
        if (this.mWidth != width || this.mHeight != height) {
            int lineWidth = (width * 30) / 225;
            this.mPath.reset();
            float vector1 = lineWidth * 0.70710677f;
            float vector2 = lineWidth / 0.70710677f;
            this.mPath.moveTo(width / 2.0f, height);
            this.mPath.lineTo(0.0f, height / 2.0f);
            this.mPath.lineTo(vector1, (height / 2.0f) - vector1);
            this.mPath.lineTo((width / 2.0f) - (lineWidth / 2.0f), (height - vector2) - (lineWidth / 2.0f));
            this.mPath.lineTo((width / 2.0f) - (lineWidth / 2.0f), 0.0f);
            this.mPath.lineTo((width / 2.0f) + (lineWidth / 2.0f), 0.0f);
            this.mPath.lineTo((width / 2.0f) + (lineWidth / 2.0f), (height - vector2) - (lineWidth / 2.0f));
            this.mPath.lineTo(width - vector1, (height / 2.0f) - vector1);
            this.mPath.lineTo(width, height / 2.0f);
            this.mPath.close();
            this.mWidth = width;
            this.mHeight = height;
        }
        canvas.drawPath(this.mPath, this.mPaint);
    }
}
