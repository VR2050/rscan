package com.ding.rtc;

import android.content.Context;
import android.graphics.PointF;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.VelocityTracker;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardGestureHandler implements ScaleGestureDetector.OnScaleGestureListener {
    private static final float MAX_CLICK_DISTANCE = 20.0f;
    private static final int MAX_CLICK_INTERVAL = 300;
    private static final float MAX_DBLCLICK_DISTANCE = 50.0f;
    private static final int MAX_DBLCLICK_INTERVAL = 500;
    private final Callback cb_;
    private final ScaleGestureDetector scaleDetector_;
    private VelocityTracker velocityTracker_;
    private PointF downPoint_ = null;
    private PointF lastPoint_ = null;
    private float maxDistance_ = 0.0f;
    private int pointerId_ = -1;
    private PointF downPoint2_ = null;
    private int pointer2Id_ = -1;
    private float downPointDistance_ = 0.0f;
    private PointF clickPoint_ = null;
    private long clickTime_ = 0;
    private ActionType action_ = ActionType.Null;
    private int pointerCount_ = 0;
    private int maxPointers_ = 0;
    private boolean scaleGesture_ = false;
    private boolean mPalmEraserEnabled = false;

    public enum ActionType {
        Drag,
        Scroll,
        Move,
        Click,
        RightClick,
        DoubleClick,
        End,
        Null
    }

    public RtcWhiteboardGestureHandler(Context ctx, Callback cb) {
        this.cb_ = cb;
        this.scaleDetector_ = new ScaleGestureDetector(ctx, this);
    }

    protected void setEnablePalmEraser(boolean enable) {
        this.mPalmEraserEnabled = enable;
    }

    protected boolean isPalmEraserEnabled() {
        return this.mPalmEraserEnabled;
    }

    public Boolean handleEvent(MotionEvent event) {
        this.scaleDetector_.onTouchEvent(event);
        if (this.scaleDetector_.isInProgress()) {
            return true;
        }
        return Boolean.valueOf(handleTouch(event));
    }

    @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
    public boolean onScaleBegin(ScaleGestureDetector detector) {
        return this.scaleGesture_;
    }

    @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
    public boolean onScale(ScaleGestureDetector detector) {
        this.cb_.onScale(detector.getScaleFactor(), detector.getFocusX(), detector.getFocusY(), detector.getCurrentSpanX(), detector.getCurrentSpanY());
        return true;
    }

    @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
    public void onScaleEnd(ScaleGestureDetector detector) {
    }

    private boolean handleTouch(MotionEvent event) {
        int pointerIndex;
        ActionType action;
        int maskedAction = event.getActionMasked();
        if (maskedAction == 0) {
            int pointerIndex2 = event.getActionIndex();
            this.pointerId_ = event.getPointerId(pointerIndex2);
            PointF pointF = new PointF();
            this.downPoint_ = pointF;
            pointF.x = event.getX(pointerIndex2);
            this.downPoint_.y = event.getY(pointerIndex2);
            this.pointer2Id_ = -1;
            this.lastPoint_ = new PointF(this.downPoint_.x, this.downPoint_.y);
            this.maxDistance_ = 0.0f;
            this.pointerCount_ = 1;
            this.maxPointers_ = 1;
            this.scaleGesture_ = false;
            this.action_ = ActionType.Null;
            VelocityTracker velocityTracker = this.velocityTracker_;
            if (velocityTracker == null) {
                this.velocityTracker_ = VelocityTracker.obtain();
            } else {
                velocityTracker.clear();
            }
            this.velocityTracker_.addMovement(event);
            this.cb_.onBegin(this.downPoint_.x, this.downPoint_.y);
            return true;
        }
        if (maskedAction == 1) {
            if (this.downPoint_ != null) {
                int pointerIndex3 = event.getActionIndex();
                float x = event.getX(pointerIndex3);
                float y = event.getY(pointerIndex3);
                ActionType action2 = ActionType.End;
                long downTime = event.getDownTime();
                long upTime = event.getEventTime();
                if (this.maxDistance_ < MAX_CLICK_DISTANCE && upTime - downTime < 300) {
                    ActionType action3 = ActionType.Click;
                    if (this.maxPointers_ == 2) {
                        ActionType action4 = ActionType.RightClick;
                        action2 = action4;
                    } else {
                        if (this.clickPoint_ != null && downTime - this.clickTime_ < 500) {
                            float dx = this.downPoint_.x - this.clickPoint_.x;
                            float dy = this.downPoint_.y - this.clickPoint_.y;
                            if (((float) Math.sqrt((dx * dx) + (dy * dy))) < MAX_DBLCLICK_DISTANCE) {
                                action2 = ActionType.DoubleClick;
                            }
                        }
                        action2 = action3;
                    }
                    if (action2 == ActionType.Click) {
                        this.clickPoint_ = new PointF(x, y);
                        this.clickTime_ = upTime;
                    } else {
                        this.clickPoint_ = null;
                        this.clickTime_ = 0L;
                    }
                } else {
                    this.clickPoint_ = null;
                    this.clickTime_ = 0L;
                }
                if (action2 == ActionType.RightClick) {
                    this.cb_.onRightClicked(x, y);
                } else if (action2 == ActionType.DoubleClick) {
                    this.cb_.onDoubleClicked(x, y);
                } else if (action2 == ActionType.Click) {
                    this.cb_.onClicked(x, y);
                } else {
                    this.cb_.onEnd(x, y);
                }
                clearMouseAction();
                return true;
            }
            return true;
        }
        if (maskedAction != 2) {
            if (maskedAction == 3) {
                this.cb_.onEnd(this.lastPoint_.x, this.lastPoint_.y);
                return true;
            }
            if (maskedAction == 5) {
                int i = this.pointerCount_ + 1;
                this.pointerCount_ = i;
                if (i == 2) {
                    int pointerIndex4 = event.getActionIndex();
                    this.pointer2Id_ = event.getPointerId(pointerIndex4);
                    PointF pointF2 = new PointF();
                    this.downPoint2_ = pointF2;
                    pointF2.x = event.getX(pointerIndex4);
                    this.downPoint2_.y = event.getY(pointerIndex4);
                    float dx2 = this.downPoint2_.x - this.downPoint_.x;
                    float dy2 = this.downPoint2_.y - this.downPoint_.y;
                    this.downPointDistance_ = (float) Math.sqrt((dx2 * dx2) + (dy2 * dy2));
                }
                this.maxPointers_++;
                this.cb_.onCancel();
                return true;
            }
            if (maskedAction == 6) {
                this.pointerCount_--;
                int pointerIndex5 = event.getActionIndex();
                int pointerId = event.getPointerId(pointerIndex5);
                if (this.pointerCount_ == 1) {
                    this.downPoint2_ = null;
                    this.pointer2Id_ = -1;
                }
                int pointerCount = event.getPointerCount();
                if (pointerId == this.pointerId_) {
                    int newPointerIndex = pointerIndex5 == 0 ? 1 : 0;
                    int newPointerIndex2 = Math.min(newPointerIndex, pointerCount - 1);
                    this.lastPoint_ = new PointF(event.getX(newPointerIndex2), event.getY(newPointerIndex2));
                    this.pointerId_ = event.getPointerId(newPointerIndex2);
                    if (this.pointerCount_ >= 2) {
                        int newPointerIndex3 = pointerIndex5 == 0 ? 2 : 1;
                        int newPointerIndex4 = Math.min(newPointerIndex3, pointerCount - 1);
                        this.downPoint2_ = new PointF(event.getX(newPointerIndex4), event.getY(newPointerIndex4));
                        this.pointer2Id_ = event.getPointerId(newPointerIndex4);
                    }
                }
                int newPointerIndex5 = this.pointer2Id_;
                if (pointerId == newPointerIndex5 && this.pointerCount_ >= 2) {
                    int newPointerIndex6 = pointerIndex5 != 1 ? 1 : 2;
                    int newPointerIndex7 = Math.min(newPointerIndex6, pointerCount - 1);
                    this.downPoint2_ = new PointF(event.getX(newPointerIndex7), event.getY(newPointerIndex7));
                    this.pointer2Id_ = event.getPointerId(newPointerIndex7);
                    return true;
                }
                return true;
            }
            return true;
        }
        if (this.lastPoint_ != null && this.downPoint_ != null && -1 != (pointerIndex = event.findPointerIndex(this.pointerId_))) {
            this.velocityTracker_.addMovement(event);
            float x2 = event.getX(pointerIndex);
            float y2 = event.getY(pointerIndex);
            float dx3 = x2 - this.downPoint_.x;
            float dy3 = y2 - this.downPoint_.y;
            ActionType action5 = this.action_;
            if (this.action_ != ActionType.Null) {
                action = action5;
            } else {
                int pointerIndex22 = event.findPointerIndex(this.pointer2Id_);
                if (-1 != pointerIndex22) {
                    float x22 = event.getX(pointerIndex22);
                    float y22 = event.getY(pointerIndex22);
                    float dx22 = x22 - x2;
                    float dy22 = y22 - y2;
                    float distance = (float) Math.sqrt((dx22 * dx22) + (dy22 * dy22));
                    if (Math.abs(distance - this.downPointDistance_) >= MAX_CLICK_DISTANCE) {
                        this.scaleGesture_ = true;
                        return true;
                    }
                }
                float x23 = dx3 * dx3;
                float d = (float) Math.sqrt(x23 + (dy3 * dy3));
                if (d > this.maxDistance_) {
                    this.maxDistance_ = d;
                }
                if (this.maxDistance_ >= MAX_CLICK_DISTANCE) {
                    int i2 = this.pointerCount_;
                    if (i2 == 2) {
                        this.action_ = ActionType.Scroll;
                    } else if (i2 == 3) {
                        this.action_ = ActionType.Drag;
                    } else {
                        this.action_ = ActionType.Move;
                    }
                    ActionType action6 = this.action_;
                    action = action6;
                } else {
                    ActionType action7 = ActionType.Move;
                    action = action7;
                }
            }
            this.velocityTracker_.computeCurrentVelocity(1000);
            float vx = this.velocityTracker_.getXVelocity(this.pointerId_);
            float vy = this.velocityTracker_.getYVelocity(this.pointerId_);
            float dx4 = x2 - this.lastPoint_.x;
            float dy4 = y2 - this.lastPoint_.y;
            this.lastPoint_.x = x2;
            this.lastPoint_.y = y2;
            if (action == ActionType.Drag) {
                this.cb_.onDrag(x2, y2, dx4, dy4, vx, vy);
                return true;
            }
            if (action == ActionType.Scroll) {
                this.cb_.onScroll(x2, y2, dx4, dy4, vx, vy);
                return true;
            }
            this.cb_.onMove(x2, y2, dx4, dy4, vx, vy);
            return true;
        }
        return true;
    }

    private void clearMouseAction() {
        this.downPoint_ = null;
        this.lastPoint_ = null;
        this.pointerId_ = -1;
        this.downPoint2_ = null;
        this.pointer2Id_ = -1;
        this.downPointDistance_ = 0.0f;
        this.maxDistance_ = 0.0f;
        this.action_ = ActionType.Null;
        this.pointerCount_ = 0;
        this.maxPointers_ = 0;
        this.scaleGesture_ = false;
        VelocityTracker velocityTracker = this.velocityTracker_;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.velocityTracker_ = null;
        }
    }

    public interface Callback {
        void onBegin(float x, float y);

        void onCancel();

        void onClicked(float x, float y);

        void onDoubleClicked(float x, float y);

        void onDrag(float x, float y, float dx, float dy, float vx, float vy);

        void onEnd(float x, float y);

        void onMove(float x, float y, float dx, float dy, float vx, float vy);

        void onPalmBegin(float x, float y, float size);

        void onPalmEnd(float x, float y);

        void onPalmMove(float x, float y);

        void onRightClicked(float x, float y);

        void onScale(float factor, float focusX, float focusY, float spanX, float spanY);

        void onScroll(float x, float y, float dx, float dy, float vx, float vy);

        /* JADX INFO: renamed from: com.ding.rtc.RtcWhiteboardGestureHandler$Callback$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$onBegin(Callback _this, float x, float y) {
            }

            public static void $default$onClicked(Callback _this, float x, float y) {
            }

            public static void $default$onRightClicked(Callback _this, float x, float y) {
            }

            public static void $default$onDoubleClicked(Callback _this, float x, float y) {
            }

            public static void $default$onMove(Callback _this, float x, float y, float dx, float dy, float vx, float vy) {
            }

            public static void $default$onDrag(Callback _this, float x, float y, float dx, float dy, float vx, float vy) {
            }

            public static void $default$onScroll(Callback _this, float x, float y, float dx, float dy, float vx, float vy) {
            }

            public static void $default$onScale(Callback _this, float factor, float focusX, float focusY, float spanX, float spanY) {
            }

            public static void $default$onEnd(Callback _this, float x, float y) {
            }

            public static void $default$onCancel(Callback _this) {
            }

            public static void $default$onPalmBegin(Callback _this, float x, float y, float size) {
            }

            public static void $default$onPalmMove(Callback _this, float x, float y) {
            }

            public static void $default$onPalmEnd(Callback _this, float x, float y) {
            }
        }
    }
}
