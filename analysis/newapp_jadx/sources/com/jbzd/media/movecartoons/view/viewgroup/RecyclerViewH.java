package com.jbzd.media.movecartoons.view.viewgroup;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class RecyclerViewH extends RecyclerView {
    private float lastX;
    private float lastY;

    public RecyclerViewH(Context context) {
        super(context);
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        boolean onInterceptTouchEvent = super.onInterceptTouchEvent(motionEvent);
        int action = motionEvent.getAction();
        if (action == 0) {
            this.lastX = motionEvent.getX();
            this.lastY = motionEvent.getY();
            return onInterceptTouchEvent;
        }
        if (action == 1) {
            return false;
        }
        if (action != 2) {
            return onInterceptTouchEvent;
        }
        float abs = Math.abs(motionEvent.getX() - this.lastX);
        float abs2 = Math.abs(motionEvent.getY() - this.lastY);
        if ((abs <= 0.0f && abs2 <= 0.0f) || abs < abs2) {
            return onInterceptTouchEvent;
        }
        requestDisallowInterceptTouchEvent(true);
        return true;
    }

    public RecyclerViewH(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    public RecyclerViewH(Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
    }
}
