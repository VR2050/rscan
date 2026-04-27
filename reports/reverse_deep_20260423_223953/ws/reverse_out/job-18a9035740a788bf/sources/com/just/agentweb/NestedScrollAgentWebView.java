package com.just.agentweb;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.core.view.MotionEventCompat;
import androidx.core.view.NestedScrollingChild;
import androidx.core.view.NestedScrollingChildHelper;

/* JADX INFO: loaded from: classes3.dex */
public class NestedScrollAgentWebView extends AgentWebView implements NestedScrollingChild {
    private NestedScrollingChildHelper mChildHelper;
    private int mLastMotionY;
    private int mNestedYOffset;
    private final int[] mScrollConsumed;
    private final int[] mScrollOffset;

    public NestedScrollAgentWebView(Context context) {
        super(context);
        this.mScrollOffset = new int[2];
        this.mScrollConsumed = new int[2];
        init();
    }

    public NestedScrollAgentWebView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mScrollOffset = new int[2];
        this.mScrollConsumed = new int[2];
        init();
    }

    private void init() {
        this.mChildHelper = new NestedScrollingChildHelper(this);
        setNestedScrollingEnabled(true);
    }

    @Override // android.webkit.WebView, android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        int deltaY;
        MotionEvent trackedEvent = MotionEvent.obtain(event);
        int action = MotionEventCompat.getActionMasked(event);
        if (action == 0) {
            this.mNestedYOffset = 0;
        }
        int y = (int) event.getY();
        event.offsetLocation(0.0f, this.mNestedYOffset);
        if (action == 0) {
            this.mLastMotionY = y;
            startNestedScroll(2);
            boolean result = super.onTouchEvent(event);
            return result;
        }
        if (action != 1) {
            if (action == 2) {
                int deltaY2 = this.mLastMotionY - y;
                if (!dispatchNestedPreScroll(0, deltaY2, this.mScrollConsumed, this.mScrollOffset)) {
                    deltaY = deltaY2;
                } else {
                    int deltaY3 = deltaY2 - this.mScrollConsumed[1];
                    trackedEvent.offsetLocation(0.0f, this.mScrollOffset[1]);
                    this.mNestedYOffset += this.mScrollOffset[1];
                    deltaY = deltaY3;
                }
                this.mLastMotionY = y - this.mScrollOffset[1];
                int oldY = getScrollY();
                int newScrollY = Math.max(0, oldY + deltaY);
                int dyConsumed = newScrollY - oldY;
                int dyUnconsumed = deltaY - dyConsumed;
                if (dispatchNestedScroll(0, dyConsumed, 0, dyUnconsumed, this.mScrollOffset)) {
                    this.mLastMotionY = this.mLastMotionY - this.mScrollOffset[1];
                    trackedEvent.offsetLocation(0.0f, r1[1]);
                    this.mNestedYOffset += this.mScrollOffset[1];
                }
                boolean result2 = super.onTouchEvent(trackedEvent);
                trackedEvent.recycle();
                return result2;
            }
            if (action != 3 && action != 5) {
                return false;
            }
        }
        stopNestedScroll();
        boolean result3 = super.onTouchEvent(event);
        return result3;
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public void setNestedScrollingEnabled(boolean enabled) {
        this.mChildHelper.setNestedScrollingEnabled(enabled);
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public boolean isNestedScrollingEnabled() {
        return this.mChildHelper.isNestedScrollingEnabled();
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public boolean startNestedScroll(int axes) {
        return this.mChildHelper.startNestedScroll(axes);
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public void stopNestedScroll() {
        this.mChildHelper.stopNestedScroll();
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public boolean hasNestedScrollingParent() {
        return this.mChildHelper.hasNestedScrollingParent();
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public boolean dispatchNestedScroll(int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int[] offsetInWindow) {
        return this.mChildHelper.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, offsetInWindow);
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public boolean dispatchNestedPreScroll(int dx, int dy, int[] consumed, int[] offsetInWindow) {
        return this.mChildHelper.dispatchNestedPreScroll(dx, dy, consumed, offsetInWindow);
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public boolean dispatchNestedFling(float velocityX, float velocityY, boolean consumed) {
        return this.mChildHelper.dispatchNestedFling(velocityX, velocityY, consumed);
    }

    @Override // android.view.View, androidx.core.view.NestedScrollingChild
    public boolean dispatchNestedPreFling(float velocityX, float velocityY) {
        return this.mChildHelper.dispatchNestedPreFling(velocityX, velocityY);
    }
}
