package com.jbzd.media.movecartoons.view.viewgroup;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.Scroller;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* loaded from: classes2.dex */
public class ScrollRecyclerView extends RecyclerView {
    private static final String TAG = ScrollRecyclerView.class.getSimpleName();
    private int childWidth;
    private int mLastX;
    private Scroller mScroller;
    private int specialLeft;
    private int specialRight;

    public ScrollRecyclerView(Context context) {
        super(context);
        this.mLastX = 0;
        init(context);
    }

    private void autoAdjustScroll(int i2, int i3) {
        this.mLastX = i2;
        this.mScroller.startScroll(i2, 0, i3 - i2, 0);
        postInvalidate();
    }

    private void init(Context context) {
        this.mScroller = new Scroller(context);
    }

    private void leftScrollBy(int i2, int i3) {
        View childAt = getChildAt(0);
        if (childAt != null) {
            autoAdjustScroll(childAt.getLeft(), i2 == i3 ? childAt.getWidth() : 0);
        }
    }

    private void rightScrollBy(int i2, int i3) {
        View childAt = getChildAt(getChildCount() - 1);
        if (childAt != null) {
            autoAdjustScroll(childAt.getRight() - getWidth(), i2 == i3 ? childAt.getWidth() * (-1) : 0);
        }
    }

    public void checkAutoAdjust(int i2) {
        getChildCount();
        int findFirstVisibleItemPosition = ((LinearLayoutManager) getLayoutManager()).findFirstVisibleItemPosition();
        int findLastVisibleItemPosition = ((LinearLayoutManager) getLayoutManager()).findLastVisibleItemPosition();
        if (i2 == findFirstVisibleItemPosition + 1 || i2 == findFirstVisibleItemPosition) {
            leftScrollBy(i2, findFirstVisibleItemPosition);
        } else if (i2 == findLastVisibleItemPosition - 1 || i2 == findLastVisibleItemPosition) {
            rightScrollBy(i2, findLastVisibleItemPosition);
        }
    }

    @Override // android.view.View
    public void computeScroll() {
        Scroller scroller = this.mScroller;
        if (scroller == null || !scroller.computeScrollOffset()) {
            return;
        }
        scrollBy(this.mLastX - this.mScroller.getCurrX(), 0);
        this.mLastX = this.mScroller.getCurrX();
        postInvalidate();
    }

    public void smoothHorizontalScrollToNext(int i2) {
        StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) getLayoutManager();
        int[] findFirstVisibleItemPositions = staggeredGridLayoutManager.findFirstVisibleItemPositions(null);
        int[] findLastVisibleItemPositions = staggeredGridLayoutManager.findLastVisibleItemPositions(null);
        if (i2 == 0) {
            int width = getWidth();
            View childAt = getChildAt(0);
            this.mLastX = 1174;
            this.mScroller.startScroll(1174, 0, -500, 0);
            postInvalidate();
            this.childWidth = childAt.getWidth();
            View childAt2 = getChildAt(findLastVisibleItemPositions[0] - 1);
            if (childAt2 == null) {
                return;
            }
            int left = childAt2.getLeft();
            this.specialLeft = left;
            this.specialRight = width - left;
        }
        View childAt3 = getChildAt(i2 - findFirstVisibleItemPositions[0]);
        if (childAt3 == null) {
            return;
        }
        int left2 = childAt3.getLeft();
        int right = childAt3.getRight();
        if (left2 > this.specialLeft) {
            this.mLastX = left2;
            this.mScroller.startScroll(left2, 0, (-this.childWidth) / 2, 0);
            postInvalidate();
        } else if (right < this.specialRight) {
            this.mLastX = right;
            this.mScroller.startScroll(right, 0, this.childWidth / 2, 0);
            postInvalidate();
        }
    }

    public void smoothScrollBy(int i2, int i3, int i4) {
        if (i4 > 0) {
            Scroller scroller = this.mScroller;
            scroller.startScroll(scroller.getFinalX(), this.mScroller.getFinalY(), i2, i3, i4);
        } else {
            Scroller scroller2 = this.mScroller;
            scroller2.startScroll(scroller2.getFinalX(), this.mScroller.getFinalY(), i2, i3);
        }
        invalidate();
    }

    public void smoothScrollTo(int i2, int i3, int i4) {
        smoothScrollBy(i2 != 0 ? i2 - this.mScroller.getFinalX() : 0, i3 != 0 ? i3 - this.mScroller.getFinalY() : 0, i4);
    }

    public ScrollRecyclerView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mLastX = 0;
        init(context);
    }

    public ScrollRecyclerView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.mLastX = 0;
        init(context);
    }
}
