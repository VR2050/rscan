package com.jbzd.media.movecartoons.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Point;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.WindowManager;
import android.widget.ImageView;
import p005b.p327w.p330b.C2827a;

@SuppressLint({"AppCompatCustomView"})
/* loaded from: classes2.dex */
public class DragView extends ImageView {
    private Context context;
    private float downX;
    private float downY;
    private int height;
    private boolean isDrag;
    private int screenHeight;
    private int screenWidth;
    private int width;

    public DragView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.isDrag = false;
        this.context = context;
    }

    public boolean isDrag() {
        return this.isDrag;
    }

    @Override // android.widget.ImageView, android.view.View
    public void onMeasure(int i2, int i3) {
        int i4;
        super.onMeasure(i2, i3);
        this.width = getMeasuredWidth();
        this.height = getMeasuredHeight();
        WindowManager windowManager = (WindowManager) C2827a.f7670a.getSystemService("window");
        int i5 = -1;
        if (windowManager == null) {
            i4 = -1;
        } else {
            Point point = new Point();
            windowManager.getDefaultDisplay().getRealSize(point);
            i4 = point.x;
        }
        this.screenWidth = i4;
        WindowManager windowManager2 = (WindowManager) C2827a.f7670a.getSystemService("window");
        if (windowManager2 != null) {
            Point point2 = new Point();
            windowManager2.getDefaultDisplay().getRealSize(point2);
            i5 = point2.y;
        }
        this.screenHeight = i5;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        super.onTouchEvent(motionEvent);
        int i2 = 0;
        if (!isEnabled()) {
            return false;
        }
        int action = motionEvent.getAction();
        if (action == 0) {
            this.isDrag = false;
            this.downX = motionEvent.getX();
            this.downY = motionEvent.getY();
        } else if (action == 1) {
            setPressed(false);
            setClickable(true);
        } else if (action == 2) {
            float x = motionEvent.getX() - this.downX;
            float y = motionEvent.getY() - this.downY;
            setClickable(Math.abs(x) < 2.0f && Math.abs(y) < 2.0f);
            if (Math.abs(x) > 10.0f || Math.abs(y) > 10.0f) {
                this.isDrag = true;
                int left = (int) (getLeft() + x);
                int i3 = this.width + left;
                int top = (int) (getTop() + y);
                int i4 = this.height;
                int i5 = top + i4;
                if (left < 0) {
                    i3 = this.width + 0;
                    left = 0;
                } else {
                    int i6 = this.screenWidth;
                    if (i3 > i6) {
                        left = i6 - this.width;
                        i3 = i6;
                    }
                }
                if (top < 0) {
                    i5 = i4 + 0;
                } else {
                    int i7 = this.screenHeight;
                    if (i5 > i7) {
                        top = i7 - i4;
                        i5 = i7;
                    }
                    i2 = top;
                }
                layout(left, i2, i3, i5);
            }
        } else if (action == 3) {
            setPressed(false);
        }
        return true;
    }
}
