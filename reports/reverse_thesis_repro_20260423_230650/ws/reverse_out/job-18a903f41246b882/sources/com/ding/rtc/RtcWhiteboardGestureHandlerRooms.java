package com.ding.rtc;

import android.content.Context;
import android.graphics.PointF;
import android.os.Build;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import com.ding.rtc.RtcWhiteboardGestureHandler;
import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import java.util.LinkedHashMap;
import java.util.Map;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardGestureHandlerRooms extends RtcWhiteboardGestureHandler {
    private static final float MAX_CLICK_DISTANCE = 20.0f;
    private static final int MAX_CLICK_INTERVAL = 300;
    private static final float MAX_DBLCLICK_DISTANCE = 50.0f;
    private static final int MAX_DBLCLICK_INTERVAL = 500;
    private static final String TAG = "[Gesture]";
    long PALM_CHECK_DURATION;
    private ActionType action_;
    PointF areaPoint;
    private final RtcWhiteboardGestureHandler.Callback cb_;
    PointF centerPoint;
    private PointF clickPoint_;
    private long clickTime_;
    private DingRtcWhiteBoardTypes.DingRtcWBGestureConfig config_;
    float density;
    private PointF downPoint2_;
    private float downPointDistance_;
    private PointF downPoint_;
    long firstDownTime;
    boolean isInPalmMode;
    private PointF lastPoint_;
    private float maxDistance_;
    private int maxPointers_;
    private float minMoveSpan_;
    private float minScrollSpan;
    private int pointer2Id_;
    private int pointerCount_;
    private int pointerId_;
    Map<Integer, PointF> pointers;
    private final CustomScaleGestureDetector scaleDetector_;
    private boolean scaleGesture_;
    private VelocityTracker velocityTracker_;

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

    public RtcWhiteboardGestureHandlerRooms(Context ctx, RtcWhiteboardGestureHandler.Callback cb, DingRtcWhiteBoardTypes.DingRtcWBGestureConfig config) {
        super(ctx, cb);
        this.minMoveSpan_ = 5.0f;
        this.minScrollSpan = 10.0f;
        this.downPoint_ = null;
        this.lastPoint_ = null;
        this.maxDistance_ = 0.0f;
        this.pointerId_ = -1;
        this.downPoint2_ = null;
        this.pointer2Id_ = -1;
        this.downPointDistance_ = 0.0f;
        this.clickPoint_ = null;
        this.clickTime_ = 0L;
        this.action_ = ActionType.Null;
        this.pointerCount_ = 0;
        this.maxPointers_ = 0;
        this.scaleGesture_ = false;
        this.density = 3.0f;
        this.isInPalmMode = false;
        this.areaPoint = new PointF();
        this.centerPoint = new PointF();
        this.PALM_CHECK_DURATION = 100L;
        this.pointers = new LinkedHashMap(10);
        this.cb_ = cb;
        this.config_ = config;
        if (config != null) {
            this.minMoveSpan_ = config.minMoveSpan;
            this.minScrollSpan = config.minScrollSpan;
            Logging.i(TAG, "config  : " + config);
        }
        this.density = ctx.getResources().getDisplayMetrics().density;
        this.scaleDetector_ = new CustomScaleGestureDetector(ctx, new CustomScaleGestureDetector.CustomOnScaleGestureListener() { // from class: com.ding.rtc.RtcWhiteboardGestureHandlerRooms.1
            @Override // com.ding.rtc.RtcWhiteboardGestureHandlerRooms.CustomScaleGestureDetector.CustomOnScaleGestureListener
            public boolean onScaleBegin(CustomScaleGestureDetector detector) {
                return RtcWhiteboardGestureHandlerRooms.this.scaleGesture_;
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandlerRooms.CustomScaleGestureDetector.CustomOnScaleGestureListener
            public boolean onScale(CustomScaleGestureDetector detector) {
                if (RtcWhiteboardGestureHandlerRooms.this.cb_ != null) {
                    RtcWhiteboardGestureHandlerRooms.this.cb_.onScale(detector.getScaleFactor(), detector.getFocusX(), detector.getFocusY(), detector.getCurrentSpanX(), detector.getCurrentSpanY());
                    return true;
                }
                return true;
            }

            @Override // com.ding.rtc.RtcWhiteboardGestureHandlerRooms.CustomScaleGestureDetector.CustomOnScaleGestureListener
            public void onScaleEnd(CustomScaleGestureDetector detector) {
            }
        }, config);
    }

    private float getPalmInfo(Map<Integer, PointF> pointers, PointF center, PointF area) {
        float left = 2.1474836E9f;
        float right = -2.1474836E9f;
        float top = 2.1474836E9f;
        float bottom = -2.1474836E9f;
        for (PointF p : pointers.values()) {
            if (p.x < left) {
                left = p.x;
            }
            if (p.x > right) {
                right = p.x;
            }
            if (p.y < top) {
                top = p.y;
            }
            if (p.y > bottom) {
                bottom = p.y;
            }
        }
        center.x = (right + left) / 2.0f;
        center.y = (bottom + top) / 2.0f;
        area.x = right - left;
        area.y = bottom - top;
        return Math.max(area.x / 2.0f, area.y / 2.0f);
    }

    @Override // com.ding.rtc.RtcWhiteboardGestureHandler
    public Boolean handleEvent(MotionEvent event) {
        if (isPalmEraserEnabled() && this.isInPalmMode) {
            return Boolean.valueOf(handleTouch(event));
        }
        this.scaleDetector_.onTouchEvent(event);
        if (this.scaleDetector_.isInProgress()) {
            return true;
        }
        return Boolean.valueOf(handleTouch(event));
    }

    /* JADX WARN: Removed duplicated region for block: B:156:0x0420  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x042f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean handleTouch(android.view.MotionEvent r24) {
        /*
            Method dump skipped, instruction units count: 1605
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ding.rtc.RtcWhiteboardGestureHandlerRooms.handleTouch(android.view.MotionEvent):boolean");
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

    static class CustomScaleGestureDetector {
        private static final int ANCHORED_SCALE_MODE_NONE = 0;
        private static final int ANCHORED_SCALE_MODE_STYLUS = 2;
        private int mAnchoredScaleMode = 0;
        private float mAnchoredScaleStartX;
        private float mAnchoredScaleStartY;
        private DingRtcWhiteBoardTypes.DingRtcWBGestureConfig mConfig;
        private float mCurrSpan;
        private float mCurrSpanX;
        private float mCurrSpanY;
        private long mCurrTime;
        private float mFocusX;
        private float mFocusY;
        private boolean mInProgress;
        private float mInitialSpan;
        private final CustomOnScaleGestureListener mListener;
        private int mMinSpan;
        private float mPrevSpan;
        private float mPrevSpanX;
        private float mPrevSpanY;
        private long mPrevTime;
        private int mSpanSlop;

        public interface CustomOnScaleGestureListener {
            boolean onScale(CustomScaleGestureDetector detector);

            boolean onScaleBegin(CustomScaleGestureDetector detector);

            void onScaleEnd(CustomScaleGestureDetector detector);
        }

        public CustomScaleGestureDetector(Context context, CustomOnScaleGestureListener listener, DingRtcWhiteBoardTypes.DingRtcWBGestureConfig config) {
            this.mListener = listener;
            this.mConfig = config;
            if (config != null) {
                this.mSpanSlop = config.minScrollSpan;
                this.mMinSpan = config.minScrollSpan;
            } else {
                this.mSpanSlop = 20;
                this.mMinSpan = 20;
            }
        }

        public boolean onTouchEvent(MotionEvent event) {
            float focusX;
            float focusY;
            float devY;
            this.mCurrTime = event.getEventTime();
            int action = event.getActionMasked();
            int count = event.getPointerCount();
            boolean isStylusButtonDown = Build.VERSION.SDK_INT >= 23 && (event.getButtonState() & 32) != 0;
            boolean anchoredScaleCancelled = this.mAnchoredScaleMode == 2 && !isStylusButtonDown;
            boolean streamComplete = action == 1 || action == 3 || anchoredScaleCancelled;
            if (action == 0 || streamComplete) {
                if (this.mInProgress) {
                    this.mListener.onScaleEnd(this);
                    this.mInProgress = false;
                    this.mInitialSpan = 0.0f;
                    this.mAnchoredScaleMode = 0;
                } else if (inAnchoredScaleMode() && streamComplete) {
                    this.mInProgress = false;
                    this.mInitialSpan = 0.0f;
                    this.mAnchoredScaleMode = 0;
                }
                if (streamComplete) {
                    return true;
                }
            }
            if (!this.mInProgress && !inAnchoredScaleMode() && !streamComplete && isStylusButtonDown) {
                this.mAnchoredScaleStartX = event.getX();
                this.mAnchoredScaleStartY = event.getY();
                this.mAnchoredScaleMode = 2;
                this.mInitialSpan = 0.0f;
            }
            boolean configChanged = action == 0 || action == 6 || action == 5 || anchoredScaleCancelled;
            boolean pointerUp = action == 6;
            int skipIndex = pointerUp ? event.getActionIndex() : -1;
            float sumX = 0.0f;
            float sumY = 0.0f;
            int div = pointerUp ? count - 1 : count;
            if (inAnchoredScaleMode()) {
                focusX = this.mAnchoredScaleStartX;
                focusY = this.mAnchoredScaleStartY;
            } else {
                for (int i = 0; i < count; i++) {
                    if (skipIndex != i) {
                        sumX += event.getX(i);
                        sumY += event.getY(i);
                    }
                }
                focusX = sumX / div;
                focusY = sumY / div;
            }
            float devSumX = 0.0f;
            float devSumY = 0.0f;
            for (int i2 = 0; i2 < count; i2++) {
                if (skipIndex != i2) {
                    devSumX += Math.abs(event.getX(i2) - focusX);
                    devSumY += Math.abs(event.getY(i2) - focusY);
                }
            }
            float devX = devSumX / div;
            float devY2 = devSumY / div;
            float spanX = devX * 2.0f;
            float spanY = devY2 * 2.0f;
            float span = inAnchoredScaleMode() ? spanY : (float) Math.hypot(spanX, spanY);
            boolean wasInProgress = this.mInProgress;
            this.mFocusX = focusX;
            this.mFocusY = focusY;
            if (!inAnchoredScaleMode() && this.mInProgress && (span < this.mMinSpan || configChanged)) {
                this.mListener.onScaleEnd(this);
                this.mInProgress = false;
                this.mInitialSpan = span;
            }
            if (configChanged) {
                this.mCurrSpanX = spanX;
                this.mPrevSpanX = spanX;
                this.mCurrSpanY = spanY;
                this.mPrevSpanY = spanY;
                this.mCurrSpan = span;
                this.mPrevSpan = span;
                this.mInitialSpan = span;
            }
            int minSpan = inAnchoredScaleMode() ? this.mSpanSlop : this.mMinSpan;
            if (this.mInProgress || span < minSpan) {
                devY = focusX;
            } else if (wasInProgress || Math.abs(span - this.mInitialSpan) > this.mSpanSlop) {
                this.mCurrSpanX = spanX;
                this.mPrevSpanX = spanX;
                this.mCurrSpanY = spanY;
                this.mPrevSpanY = spanY;
                this.mCurrSpan = span;
                this.mPrevSpan = span;
                devY = focusX;
                this.mPrevTime = this.mCurrTime;
                this.mInProgress = this.mListener.onScaleBegin(this);
            } else {
                devY = focusX;
            }
            if (action == 2) {
                this.mCurrSpanX = spanX;
                this.mCurrSpanY = spanY;
                this.mCurrSpan = span;
                boolean updatePrev = true;
                if (this.mInProgress) {
                    updatePrev = this.mListener.onScale(this);
                }
                if (updatePrev) {
                    this.mPrevSpanX = this.mCurrSpanX;
                    this.mPrevSpanY = this.mCurrSpanY;
                    this.mPrevSpan = this.mCurrSpan;
                    this.mPrevTime = this.mCurrTime;
                    return true;
                }
                return true;
            }
            return true;
        }

        private boolean inAnchoredScaleMode() {
            return this.mAnchoredScaleMode != 0;
        }

        public boolean isInProgress() {
            return this.mInProgress;
        }

        public float getFocusX() {
            return this.mFocusX;
        }

        public float getFocusY() {
            return this.mFocusY;
        }

        public float getCurrentSpan() {
            return this.mCurrSpan;
        }

        public float getCurrentSpanX() {
            return this.mCurrSpanX;
        }

        public float getCurrentSpanY() {
            return this.mCurrSpanY;
        }

        public float getPreviousSpan() {
            return this.mPrevSpan;
        }

        public float getPreviousSpanX() {
            return this.mPrevSpanX;
        }

        public float getPreviousSpanY() {
            return this.mPrevSpanY;
        }

        public float getScaleFactor() {
            float f = this.mPrevSpan;
            if (f > 0.0f) {
                return this.mCurrSpan / f;
            }
            return 1.0f;
        }

        public long getTimeDelta() {
            return this.mCurrTime - this.mPrevTime;
        }

        public long getEventTime() {
            return this.mCurrTime;
        }
    }
}
