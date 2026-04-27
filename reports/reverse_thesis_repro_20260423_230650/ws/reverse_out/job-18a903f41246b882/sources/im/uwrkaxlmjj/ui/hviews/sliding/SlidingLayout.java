package im.uwrkaxlmjj.ui.hviews.sliding;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Build;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.AbsListView;
import android.widget.FrameLayout;
import android.widget.ListAdapter;
import androidx.core.view.MotionEventCompat;
import androidx.core.view.ViewCompat;
import im.uwrkaxlmjj.messenger.R;

/* JADX INFO: loaded from: classes5.dex */
public class SlidingLayout extends FrameLayout {
    private static final int INVALID_POINTER = -1;
    private static final int RESET_DURATION = 200;
    public static final int SLIDING_DISTANCE_UNDEFINED = -1;
    public static final int SLIDING_MODE_BOTH = 0;
    public static final int SLIDING_MODE_BOTTOM = 2;
    public static final int SLIDING_MODE_TOP = 1;
    public static final int SLIDING_POINTER_MODE_MORE = 1;
    public static final int SLIDING_POINTER_MODE_ONE = 0;
    private static final int SMOOTH_DURATION = 1000;
    public static final int STATE_IDLE = 1;
    public static final int STATE_SLIDING = 2;
    private int mActivePointerId;
    private View mBackgroundView;
    private int mBackgroundViewLayoutId;
    private View.OnTouchListener mDelegateTouchListener;
    private View mFollowView;
    private float mInitialDownY;
    private float mInitialMotionY;
    private boolean mIsBeingDragged;
    private float mLastMotionY;
    private SlidingListener mSlidingListener;
    private int mSlidingMode;
    private float mSlidingOffset;
    private int mSlidingPointerMode;
    private int mSlidingTopMaxDistance;
    private View mTargetView;
    private int mTouchSlop;

    public interface SlidingListener {
        void onSlidingChangePointer(View view, int i);

        void onSlidingOffset(View view, float f);

        void onSlidingStateChange(View view, int i);
    }

    public SlidingLayout(Context context) {
        this(context, null);
    }

    public SlidingLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SlidingLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mBackgroundViewLayoutId = 0;
        this.mActivePointerId = -1;
        this.mSlidingOffset = 0.5f;
        this.mSlidingMode = 0;
        this.mSlidingPointerMode = 1;
        this.mSlidingTopMaxDistance = -1;
        init(context, attrs);
    }

    private void init(Context context, AttributeSet attrs) {
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SlidingLayout);
        this.mBackgroundViewLayoutId = a.getResourceId(0, this.mBackgroundViewLayoutId);
        this.mSlidingMode = a.getInteger(1, 0);
        this.mSlidingPointerMode = a.getInteger(2, 1);
        this.mSlidingTopMaxDistance = a.getDimensionPixelSize(3, -1);
        a.recycle();
        if (this.mBackgroundViewLayoutId != 0) {
            View view = View.inflate(getContext(), this.mBackgroundViewLayoutId, null);
            setBackgroundView(view);
        }
        this.mTouchSlop = ViewConfiguration.get(getContext()).getScaledTouchSlop();
    }

    public void setBackgroundView(View view) {
        View view2 = this.mBackgroundView;
        if (view2 != null) {
            removeView(view2);
        }
        this.mBackgroundView = view;
        addView(view, 0);
    }

    public View getBackgroundView() {
        return this.mBackgroundView;
    }

    public void setSlidingDistance(int distance) {
        this.mSlidingTopMaxDistance = distance;
    }

    public int setSlidingDistance() {
        return this.mSlidingTopMaxDistance;
    }

    public float getSlidingOffset() {
        return this.mSlidingOffset;
    }

    public void setSlidingOffset(float slidingOffset) {
        this.mSlidingOffset = slidingOffset;
    }

    public void setSlidingListener(SlidingListener slidingListener) {
        this.mSlidingListener = slidingListener;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        if (getChildCount() == 0) {
            return;
        }
        if (this.mTargetView == null) {
            ensureTarget();
        }
        if (this.mTargetView == null) {
        }
    }

    private void ensureTarget() {
        if (this.mTargetView == null) {
            this.mTargetView = getChildAt(getChildCount() - 1);
        }
    }

    public void setTargetView(View view) {
        View view2 = this.mTargetView;
        if (view2 != null) {
            removeView(view2);
        }
        this.mTargetView = view;
        addView(view);
    }

    public void setFollowView(View view) {
        this.mFollowView = view;
    }

    @Override // android.view.View
    public void setOnTouchListener(View.OnTouchListener l) {
        this.mDelegateTouchListener = l;
    }

    public View getTargetView() {
        return this.mTargetView;
    }

    public float getSlidingDistance() {
        return getInstrument().getTranslationY(getTargetView());
    }

    public Instrument getInstrument() {
        return Instrument.getInstance();
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0070  */
    @Override // android.view.ViewGroup
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onInterceptTouchEvent(android.view.MotionEvent r7) {
        /*
            r6 = this;
            r6.ensureTarget()
            int r0 = androidx.core.view.MotionEventCompat.getActionMasked(r7)
            r1 = -1082130432(0xffffffffbf800000, float:-1.0)
            r2 = 0
            if (r0 == 0) goto L75
            r3 = -1
            r4 = 1
            if (r0 == r4) goto L70
            r5 = 2
            if (r0 == r5) goto L18
            r1 = 3
            if (r0 == r1) goto L70
            goto L89
        L18:
            int r5 = r6.mActivePointerId
            if (r5 != r3) goto L1d
            return r2
        L1d:
            float r3 = r6.getMotionEventY(r7, r5)
            int r1 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r1 != 0) goto L26
            return r2
        L26:
            float r1 = r6.mInitialDownY
            int r2 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r2 <= 0) goto L4c
            float r1 = r3 - r1
            int r2 = r6.mTouchSlop
            float r2 = (float) r2
            int r2 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r2 <= 0) goto L6f
            boolean r2 = r6.mIsBeingDragged
            if (r2 != 0) goto L6f
            boolean r2 = r6.canChildScrollUp()
            if (r2 != 0) goto L6f
            float r2 = r6.mInitialDownY
            int r5 = r6.mTouchSlop
            float r5 = (float) r5
            float r2 = r2 + r5
            r6.mInitialMotionY = r2
            r6.mLastMotionY = r2
            r6.mIsBeingDragged = r4
            goto L6f
        L4c:
            int r2 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r2 >= 0) goto L6f
            float r1 = r1 - r3
            int r2 = r6.mTouchSlop
            float r2 = (float) r2
            int r2 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r2 <= 0) goto L6e
            boolean r2 = r6.mIsBeingDragged
            if (r2 != 0) goto L6e
            boolean r2 = r6.canChildScrollDown()
            if (r2 != 0) goto L6e
            float r2 = r6.mInitialDownY
            int r5 = r6.mTouchSlop
            float r5 = (float) r5
            float r2 = r2 + r5
            r6.mInitialMotionY = r2
            r6.mLastMotionY = r2
            r6.mIsBeingDragged = r4
        L6e:
            goto L89
        L6f:
            goto L89
        L70:
            r6.mIsBeingDragged = r2
            r6.mActivePointerId = r3
            goto L89
        L75:
            int r3 = androidx.core.view.MotionEventCompat.getPointerId(r7, r2)
            r6.mActivePointerId = r3
            r6.mIsBeingDragged = r2
            float r3 = r6.getMotionEventY(r7, r3)
            int r1 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r1 != 0) goto L86
            return r2
        L86:
            r6.mInitialDownY = r3
        L89:
            boolean r1 = r6.mIsBeingDragged
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hviews.sliding.SlidingLayout.onInterceptTouchEvent(android.view.MotionEvent):boolean");
    }

    private float getMotionEventY(MotionEvent ev, int activePointerId) {
        int index = MotionEventCompat.findPointerIndex(ev, activePointerId);
        if (index < 0) {
            return -1.0f;
        }
        return MotionEventCompat.getY(ev, index);
    }

    public boolean canChildScrollUp() {
        if (Build.VERSION.SDK_INT < 14) {
            View view = this.mTargetView;
            if (!(view instanceof AbsListView)) {
                return ViewCompat.canScrollVertically(view, -1) || this.mTargetView.getScrollY() > 0;
            }
            AbsListView absListView = (AbsListView) view;
            return absListView.getChildCount() > 0 && (absListView.getFirstVisiblePosition() > 0 || absListView.getChildAt(0).getTop() < absListView.getPaddingTop());
        }
        return ViewCompat.canScrollVertically(this.mTargetView, -1);
    }

    public boolean canChildScrollDown() {
        if (Build.VERSION.SDK_INT < 14) {
            View view = this.mTargetView;
            if (!(view instanceof AbsListView)) {
                return ViewCompat.canScrollVertically(view, 1) || this.mTargetView.getScrollY() > 0;
            }
            AbsListView absListView = (AbsListView) view;
            return absListView.getChildCount() > 0 && absListView.getAdapter() != null && (absListView.getLastVisiblePosition() < ((ListAdapter) absListView.getAdapter()).getCount() - 1 || absListView.getChildAt(absListView.getChildCount() - 1).getBottom() < absListView.getPaddingBottom());
        }
        return ViewCompat.canScrollVertically(this.mTargetView, 1);
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent event) {
        return super.dispatchTouchEvent(event);
    }

    /* JADX WARN: Removed duplicated region for block: B:55:0x011d  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r9) {
        /*
            Method dump skipped, instruction units count: 306
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hviews.sliding.SlidingLayout.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public void setSlidingMode(int mode) {
        this.mSlidingMode = mode;
    }

    public int getSlidingMode() {
        return this.mSlidingMode;
    }

    public void smoothScrollTo(float y) {
        getInstrument().smoothTo(this.mTargetView, y, 1000L);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        View view = this.mTargetView;
        if (view != null) {
            view.clearAnimation();
        }
        this.mSlidingMode = 0;
        this.mTargetView = null;
        this.mBackgroundView = null;
        this.mSlidingListener = null;
    }
}
