package com.google.android.material.appbar;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.OverScroller;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.math.MathUtils;
import androidx.core.view.ViewCompat;

/* JADX INFO: loaded from: classes.dex */
abstract class HeaderBehavior<V extends View> extends ViewOffsetBehavior<V> {
    private static final int INVALID_POINTER = -1;
    private int activePointerId;
    private Runnable flingRunnable;
    private boolean isBeingDragged;
    private int lastMotionY;
    OverScroller scroller;
    private int touchSlop;
    private VelocityTracker velocityTracker;

    public HeaderBehavior() {
        this.activePointerId = -1;
        this.touchSlop = -1;
    }

    public HeaderBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.activePointerId = -1;
        this.touchSlop = -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0051  */
    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onInterceptTouchEvent(androidx.coordinatorlayout.widget.CoordinatorLayout r8, V r9, android.view.MotionEvent r10) {
        /*
            r7 = this;
            int r0 = r7.touchSlop
            if (r0 >= 0) goto L12
            android.content.Context r0 = r8.getContext()
            android.view.ViewConfiguration r0 = android.view.ViewConfiguration.get(r0)
            int r0 = r0.getScaledTouchSlop()
            r7.touchSlop = r0
        L12:
            int r0 = r10.getAction()
            r1 = 2
            r2 = 1
            if (r0 != r1) goto L1f
            boolean r3 = r7.isBeingDragged
            if (r3 == 0) goto L1f
            return r2
        L1f:
            int r3 = r10.getActionMasked()
            r4 = 0
            if (r3 == 0) goto L60
            r5 = -1
            if (r3 == r2) goto L51
            if (r3 == r1) goto L2f
            r1 = 3
            if (r3 == r1) goto L51
            goto L83
        L2f:
            int r1 = r7.activePointerId
            if (r1 != r5) goto L34
            goto L83
        L34:
            int r3 = r10.findPointerIndex(r1)
            if (r3 != r5) goto L3b
            goto L83
        L3b:
            float r4 = r10.getY(r3)
            int r4 = (int) r4
            int r5 = r7.lastMotionY
            int r5 = r4 - r5
            int r5 = java.lang.Math.abs(r5)
            int r6 = r7.touchSlop
            if (r5 <= r6) goto L83
            r7.isBeingDragged = r2
            r7.lastMotionY = r4
            goto L83
        L51:
            r7.isBeingDragged = r4
            r7.activePointerId = r5
            android.view.VelocityTracker r1 = r7.velocityTracker
            if (r1 == 0) goto L83
            r1.recycle()
            r1 = 0
            r7.velocityTracker = r1
            goto L83
        L60:
            r7.isBeingDragged = r4
            float r1 = r10.getX()
            int r1 = (int) r1
            float r2 = r10.getY()
            int r2 = (int) r2
            boolean r3 = r7.canDragView(r9)
            if (r3 == 0) goto L83
            boolean r3 = r8.isPointInChildBounds(r9, r1, r2)
            if (r3 == 0) goto L83
            r7.lastMotionY = r2
            int r3 = r10.getPointerId(r4)
            r7.activePointerId = r3
            r7.ensureVelocityTracker()
        L83:
            android.view.VelocityTracker r1 = r7.velocityTracker
            if (r1 == 0) goto L8a
            r1.addMovement(r10)
        L8a:
            boolean r1 = r7.isBeingDragged
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.appbar.HeaderBehavior.onInterceptTouchEvent(androidx.coordinatorlayout.widget.CoordinatorLayout, android.view.View, android.view.MotionEvent):boolean");
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onTouchEvent(CoordinatorLayout parent, V child, MotionEvent ev) {
        if (this.touchSlop < 0) {
            this.touchSlop = ViewConfiguration.get(parent.getContext()).getScaledTouchSlop();
        }
        int actionMasked = ev.getActionMasked();
        if (actionMasked == 0) {
            int x = (int) ev.getX();
            int y = (int) ev.getY();
            if (!parent.isPointInChildBounds(child, x, y) || !canDragView(child)) {
                return false;
            }
            this.lastMotionY = y;
            this.activePointerId = ev.getPointerId(0);
            ensureVelocityTracker();
        } else {
            if (actionMasked == 1) {
                VelocityTracker velocityTracker = this.velocityTracker;
                if (velocityTracker != null) {
                    velocityTracker.addMovement(ev);
                    this.velocityTracker.computeCurrentVelocity(1000);
                    float yvel = this.velocityTracker.getYVelocity(this.activePointerId);
                    fling(parent, child, -getScrollRangeForDragFling(child), 0, yvel);
                }
            } else if (actionMasked == 2) {
                int activePointerIndex = ev.findPointerIndex(this.activePointerId);
                if (activePointerIndex == -1) {
                    return false;
                }
                int y2 = (int) ev.getY(activePointerIndex);
                int dy = this.lastMotionY - y2;
                if (!this.isBeingDragged) {
                    int iAbs = Math.abs(dy);
                    int i = this.touchSlop;
                    if (iAbs > i) {
                        this.isBeingDragged = true;
                        dy = dy > 0 ? dy - i : dy + i;
                    }
                }
                if (this.isBeingDragged) {
                    this.lastMotionY = y2;
                    scroll(parent, child, dy, getMaxDragOffset(child), 0);
                }
            } else if (actionMasked == 3) {
            }
            this.isBeingDragged = false;
            this.activePointerId = -1;
            VelocityTracker velocityTracker2 = this.velocityTracker;
            if (velocityTracker2 != null) {
                velocityTracker2.recycle();
                this.velocityTracker = null;
            }
        }
        VelocityTracker velocityTracker3 = this.velocityTracker;
        if (velocityTracker3 != null) {
            velocityTracker3.addMovement(ev);
        }
        return true;
    }

    int setHeaderTopBottomOffset(CoordinatorLayout parent, V header, int newOffset) {
        return setHeaderTopBottomOffset(parent, header, newOffset, Integer.MIN_VALUE, Integer.MAX_VALUE);
    }

    int setHeaderTopBottomOffset(CoordinatorLayout parent, V header, int newOffset, int minOffset, int maxOffset) {
        int newOffset2;
        int curOffset = getTopAndBottomOffset();
        if (minOffset == 0 || curOffset < minOffset || curOffset > maxOffset || curOffset == (newOffset2 = MathUtils.clamp(newOffset, minOffset, maxOffset))) {
            return 0;
        }
        setTopAndBottomOffset(newOffset2);
        int consumed = curOffset - newOffset2;
        return consumed;
    }

    int getTopBottomOffsetForScrollingSibling() {
        return getTopAndBottomOffset();
    }

    final int scroll(CoordinatorLayout coordinatorLayout, V header, int dy, int minOffset, int maxOffset) {
        return setHeaderTopBottomOffset(coordinatorLayout, header, getTopBottomOffsetForScrollingSibling() - dy, minOffset, maxOffset);
    }

    final boolean fling(CoordinatorLayout coordinatorLayout, V layout, int minOffset, int maxOffset, float velocityY) {
        Runnable runnable = this.flingRunnable;
        if (runnable != null) {
            layout.removeCallbacks(runnable);
            this.flingRunnable = null;
        }
        if (this.scroller == null) {
            this.scroller = new OverScroller(layout.getContext());
        }
        this.scroller.fling(0, getTopAndBottomOffset(), 0, Math.round(velocityY), 0, 0, minOffset, maxOffset);
        if (this.scroller.computeScrollOffset()) {
            FlingRunnable flingRunnable = new FlingRunnable(coordinatorLayout, layout);
            this.flingRunnable = flingRunnable;
            ViewCompat.postOnAnimation(layout, flingRunnable);
            return true;
        }
        onFlingFinished(coordinatorLayout, layout);
        return false;
    }

    void onFlingFinished(CoordinatorLayout parent, V layout) {
    }

    boolean canDragView(V view) {
        return false;
    }

    int getMaxDragOffset(V view) {
        return -view.getHeight();
    }

    int getScrollRangeForDragFling(V view) {
        return view.getHeight();
    }

    private void ensureVelocityTracker() {
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
    }

    private class FlingRunnable implements Runnable {
        private final V layout;
        private final CoordinatorLayout parent;

        FlingRunnable(CoordinatorLayout parent, V layout) {
            this.parent = parent;
            this.layout = layout;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.layout != null && HeaderBehavior.this.scroller != null) {
                if (HeaderBehavior.this.scroller.computeScrollOffset()) {
                    HeaderBehavior headerBehavior = HeaderBehavior.this;
                    headerBehavior.setHeaderTopBottomOffset(this.parent, this.layout, headerBehavior.scroller.getCurrY());
                    ViewCompat.postOnAnimation(this.layout, this);
                    return;
                }
                HeaderBehavior.this.onFlingFinished(this.parent, this.layout);
            }
        }
    }
}
