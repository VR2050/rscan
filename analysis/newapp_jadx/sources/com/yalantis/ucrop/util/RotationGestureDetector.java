package com.yalantis.ucrop.util;

import android.view.MotionEvent;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class RotationGestureDetector {
    private static final int INVALID_POINTER_INDEX = -1;

    /* renamed from: fX */
    private float f10923fX;

    /* renamed from: fY */
    private float f10924fY;
    private float mAngle;
    private boolean mIsFirstTouch;
    private OnRotationGestureListener mListener;
    private int mPointerIndex1 = -1;
    private int mPointerIndex2 = -1;

    /* renamed from: sX */
    private float f10925sX;

    /* renamed from: sY */
    private float f10926sY;

    public interface OnRotationGestureListener {
        boolean onRotation(RotationGestureDetector rotationGestureDetector);
    }

    public static class SimpleOnRotationGestureListener implements OnRotationGestureListener {
        @Override // com.yalantis.ucrop.util.RotationGestureDetector.OnRotationGestureListener
        public boolean onRotation(RotationGestureDetector rotationGestureDetector) {
            return false;
        }
    }

    public RotationGestureDetector(OnRotationGestureListener onRotationGestureListener) {
        this.mListener = onRotationGestureListener;
    }

    private float calculateAngleBetweenLines(float f2, float f3, float f4, float f5, float f6, float f7, float f8, float f9) {
        return calculateAngleDelta((float) Math.toDegrees((float) Math.atan2(f3 - f5, f2 - f4)), (float) Math.toDegrees((float) Math.atan2(f7 - f9, f6 - f8)));
    }

    private float calculateAngleDelta(float f2, float f3) {
        float f4 = (f3 % 360.0f) - (f2 % 360.0f);
        this.mAngle = f4;
        if (f4 < -180.0f) {
            this.mAngle = f4 + 360.0f;
        } else if (f4 > 180.0f) {
            this.mAngle = f4 - 360.0f;
        }
        return this.mAngle;
    }

    public float getAngle() {
        return this.mAngle;
    }

    public boolean onTouchEvent(@NonNull MotionEvent motionEvent) {
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 0) {
            this.f10925sX = motionEvent.getX();
            this.f10926sY = motionEvent.getY();
            this.mPointerIndex1 = motionEvent.findPointerIndex(motionEvent.getPointerId(0));
            this.mAngle = 0.0f;
            this.mIsFirstTouch = true;
        } else if (actionMasked == 1) {
            this.mPointerIndex1 = -1;
        } else if (actionMasked != 2) {
            if (actionMasked == 5) {
                this.f10923fX = motionEvent.getX();
                this.f10924fY = motionEvent.getY();
                this.mPointerIndex2 = motionEvent.findPointerIndex(motionEvent.getPointerId(motionEvent.getActionIndex()));
                this.mAngle = 0.0f;
                this.mIsFirstTouch = true;
            } else if (actionMasked == 6) {
                this.mPointerIndex2 = -1;
            }
        } else if (this.mPointerIndex1 != -1 && this.mPointerIndex2 != -1 && motionEvent.getPointerCount() > this.mPointerIndex2) {
            float x = motionEvent.getX(this.mPointerIndex1);
            float y = motionEvent.getY(this.mPointerIndex1);
            float x2 = motionEvent.getX(this.mPointerIndex2);
            float y2 = motionEvent.getY(this.mPointerIndex2);
            if (this.mIsFirstTouch) {
                this.mAngle = 0.0f;
                this.mIsFirstTouch = false;
            } else {
                calculateAngleBetweenLines(this.f10923fX, this.f10924fY, this.f10925sX, this.f10926sY, x2, y2, x, y);
            }
            OnRotationGestureListener onRotationGestureListener = this.mListener;
            if (onRotationGestureListener != null) {
                onRotationGestureListener.onRotation(this);
            }
            this.f10923fX = x2;
            this.f10924fY = y2;
            this.f10925sX = x;
            this.f10926sY = y;
        }
        return true;
    }
}
