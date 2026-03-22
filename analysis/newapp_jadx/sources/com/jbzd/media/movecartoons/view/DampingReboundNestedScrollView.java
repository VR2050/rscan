package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.Interpolator;
import android.view.animation.TranslateAnimation;
import androidx.core.widget.NestedScrollView;

/* loaded from: classes2.dex */
public class DampingReboundNestedScrollView extends NestedScrollView {
    private View childView;
    private int currentY;
    private int deltaY;
    private float moveHeight;
    private int previousY;
    private int startY;
    private Rect topRect;

    public class DampInterpolator implements Interpolator {
        public DampInterpolator() {
        }

        @Override // android.animation.TimeInterpolator
        public float getInterpolation(float f2) {
            float f3 = 1.0f - f2;
            return 1.0f - ((((f3 * f3) * f3) * f3) * f3);
        }
    }

    public DampingReboundNestedScrollView(Context context) {
        this(context, null);
    }

    private void upDownMoveAnimation() {
        TranslateAnimation translateAnimation = new TranslateAnimation(0.0f, 0.0f, this.childView.getTop(), this.topRect.top);
        translateAnimation.setDuration(600L);
        translateAnimation.setFillAfter(true);
        translateAnimation.setInterpolator(new DampInterpolator());
        this.childView.setAnimation(translateAnimation);
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent motionEvent) {
        if (this.childView == null) {
            return super.dispatchTouchEvent(motionEvent);
        }
        int action = motionEvent.getAction();
        float f2 = 0.0f;
        if (action == 0) {
            int y = (int) motionEvent.getY();
            this.startY = y;
            this.previousY = y;
            this.topRect.set(this.childView.getLeft(), this.childView.getTop(), this.childView.getRight(), this.childView.getBottom());
            this.moveHeight = 0.0f;
        } else if (action == 1) {
            if (!this.topRect.isEmpty()) {
                upDownMoveAnimation();
                View view = this.childView;
                Rect rect = this.topRect;
                view.layout(rect.left, rect.top, rect.right, rect.bottom);
            }
            this.startY = 0;
            this.currentY = 0;
            this.topRect.setEmpty();
        } else if (action == 2) {
            int y2 = (int) motionEvent.getY();
            this.currentY = y2;
            this.deltaY = y2 - this.previousY;
            this.previousY = y2;
            if ((!this.childView.canScrollVertically(-1) && this.currentY - this.startY > 0) || (!this.childView.canScrollVertically(1) && this.currentY - this.startY < 0)) {
                float f3 = this.currentY - this.startY;
                if (f3 < 0.0f) {
                    f3 *= -1.0f;
                }
                float height = getHeight();
                if (height == 0.0f) {
                    f2 = 0.5f;
                } else if (f3 <= height) {
                    f2 = (height - f3) / height;
                }
                if (this.currentY - this.startY < 0) {
                    f2 = 1.0f - f2;
                }
                float f4 = (this.deltaY * ((float) (((float) (f2 * 0.25d)) + 0.25d))) + this.moveHeight;
                this.moveHeight = f4;
                View view2 = this.childView;
                Rect rect2 = this.topRect;
                view2.layout(rect2.left, (int) (rect2.top + f4), rect2.right, (int) (rect2.bottom + f4));
            }
        }
        return super.dispatchTouchEvent(motionEvent);
    }

    @Override // android.view.View
    public void onFinishInflate() {
        super.onFinishInflate();
        if (getChildCount() > 0) {
            this.childView = getChildAt(0);
        }
    }

    public DampingReboundNestedScrollView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public DampingReboundNestedScrollView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.previousY = 0;
        this.startY = 0;
        this.currentY = 0;
        this.deltaY = 0;
        this.topRect = new Rect();
        setFillViewport(true);
    }
}
