package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class LooperLayoutManager extends LinearLayoutManager {
    private static final String TAG = "LooperLayoutManager";
    private boolean looperEnable;
    private boolean scrollHorizontal;
    private boolean scrollVertical;

    public LooperLayoutManager(Context context) {
        super(context);
        this.looperEnable = true;
        this.scrollVertical = true;
        this.scrollHorizontal = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x003c A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:17:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0089 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x008a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int fillHorizontal(int r9, androidx.recyclerview.widget.RecyclerView.Recycler r10, androidx.recyclerview.widget.RecyclerView.State r11) {
        /*
            r8 = this;
            r11 = 0
            r0 = 0
            if (r9 <= 0) goto L5b
            int r1 = r8.getChildCount()
            int r1 = r1 + (-1)
            android.view.View r1 = r8.getChildAt(r1)
            if (r1 != 0) goto L11
            return r0
        L11:
            int r2 = r8.getPosition(r1)
            int r3 = r1.getRight()
            int r4 = r8.getWidth()
            if (r3 >= r4) goto La7
            int r3 = r8.getItemCount()
            int r3 = r3 + (-1)
            if (r2 != r3) goto L33
            boolean r2 = r8.looperEnable
            if (r2 == 0) goto L30
            android.view.View r11 = r10.getViewForPosition(r0)
            goto L39
        L30:
            r3 = r11
            r9 = 0
            goto L3a
        L33:
            int r2 = r2 + 1
            android.view.View r11 = r10.getViewForPosition(r2)
        L39:
            r3 = r11
        L3a:
            if (r3 != 0) goto L3d
            return r9
        L3d:
            r8.addView(r3)
            r8.measureChildWithMargins(r3, r0, r0)
            int r10 = r8.getDecoratedMeasuredWidth(r3)
            int r7 = r8.getDecoratedMeasuredHeight(r3)
            int r4 = r1.getRight()
            r5 = 0
            int r11 = r1.getRight()
            int r6 = r11 + r10
            r2 = r8
            r2.layoutDecorated(r3, r4, r5, r6, r7)
            return r9
        L5b:
            android.view.View r1 = r8.getChildAt(r0)
            if (r1 != 0) goto L62
            return r0
        L62:
            int r2 = r8.getPosition(r1)
            int r3 = r1.getLeft()
            if (r3 < 0) goto La7
            if (r2 != 0) goto L80
            boolean r2 = r8.looperEnable
            if (r2 == 0) goto L7d
            int r11 = r8.getItemCount()
            int r11 = r11 + (-1)
            android.view.View r11 = r10.getViewForPosition(r11)
            goto L86
        L7d:
            r3 = r11
            r9 = 0
            goto L87
        L80:
            int r2 = r2 + (-1)
            android.view.View r11 = r10.getViewForPosition(r2)
        L86:
            r3 = r11
        L87:
            if (r3 != 0) goto L8a
            return r0
        L8a:
            r8.addView(r3, r0)
            r8.measureChildWithMargins(r3, r0, r0)
            int r10 = r8.getDecoratedMeasuredWidth(r3)
            int r7 = r8.getDecoratedMeasuredHeight(r3)
            int r11 = r1.getLeft()
            int r4 = r11 - r10
            r5 = 0
            int r6 = r1.getLeft()
            r2 = r8
            r2.layoutDecorated(r3, r4, r5, r6, r7)
        La7:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.view.LooperLayoutManager.fillHorizontal(int, androidx.recyclerview.widget.RecyclerView$Recycler, androidx.recyclerview.widget.RecyclerView$State):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x003c A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:17:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0089 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x008a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int fillVertical(int r9, androidx.recyclerview.widget.RecyclerView.Recycler r10, androidx.recyclerview.widget.RecyclerView.State r11) {
        /*
            r8 = this;
            r11 = 0
            r0 = 0
            if (r9 <= 0) goto L5b
            int r1 = r8.getChildCount()
            int r1 = r1 + (-1)
            android.view.View r1 = r8.getChildAt(r1)
            if (r1 != 0) goto L11
            return r0
        L11:
            int r2 = r8.getPosition(r1)
            int r3 = r1.getBottom()
            int r4 = r8.getHeight()
            if (r3 >= r4) goto La7
            int r3 = r8.getItemCount()
            int r3 = r3 + (-1)
            if (r2 != r3) goto L33
            boolean r2 = r8.looperEnable
            if (r2 == 0) goto L30
            android.view.View r11 = r10.getViewForPosition(r0)
            goto L39
        L30:
            r3 = r11
            r9 = 0
            goto L3a
        L33:
            int r2 = r2 + 1
            android.view.View r11 = r10.getViewForPosition(r2)
        L39:
            r3 = r11
        L3a:
            if (r3 != 0) goto L3d
            return r9
        L3d:
            r8.addView(r3)
            r8.measureChildWithMargins(r3, r0, r0)
            int r6 = r8.getDecoratedMeasuredWidth(r3)
            int r10 = r8.getDecoratedMeasuredHeight(r3)
            r4 = 0
            int r5 = r1.getBottom()
            int r11 = r1.getBottom()
            int r7 = r11 + r10
            r2 = r8
            r2.layoutDecorated(r3, r4, r5, r6, r7)
            return r9
        L5b:
            android.view.View r1 = r8.getChildAt(r0)
            if (r1 != 0) goto L62
            return r0
        L62:
            int r2 = r8.getPosition(r1)
            int r3 = r1.getTop()
            if (r3 < 0) goto La7
            if (r2 != 0) goto L80
            boolean r2 = r8.looperEnable
            if (r2 == 0) goto L7d
            int r11 = r8.getItemCount()
            int r11 = r11 + (-1)
            android.view.View r11 = r10.getViewForPosition(r11)
            goto L86
        L7d:
            r3 = r11
            r9 = 0
            goto L87
        L80:
            int r2 = r2 + (-1)
            android.view.View r11 = r10.getViewForPosition(r2)
        L86:
            r3 = r11
        L87:
            if (r3 != 0) goto L8a
            return r0
        L8a:
            r8.addView(r3, r0)
            r8.measureChildWithMargins(r3, r0, r0)
            int r6 = r8.getDecoratedMeasuredWidth(r3)
            int r10 = r8.getDecoratedMeasuredHeight(r3)
            r4 = 0
            int r11 = r1.getTop()
            int r5 = r11 - r10
            int r7 = r1.getTop()
            r2 = r8
            r2.layoutDecorated(r3, r4, r5, r6, r7)
        La7:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.view.LooperLayoutManager.fillVertical(int, androidx.recyclerview.widget.RecyclerView$Recycler, androidx.recyclerview.widget.RecyclerView$State):int");
    }

    private void recyclerHorizontalHideView(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        for (int i3 = 0; i3 < getChildCount(); i3++) {
            View childAt = getChildAt(i3);
            if (childAt != null) {
                if (i2 > 0) {
                    if (childAt.getRight() < 0) {
                        removeAndRecycleView(childAt, recycler);
                        getChildCount();
                    }
                } else if (childAt.getLeft() > getWidth()) {
                    removeAndRecycleView(childAt, recycler);
                    getChildCount();
                }
            }
        }
    }

    private void recyclerVerticalHideView(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        for (int i3 = 0; i3 < getChildCount(); i3++) {
            View childAt = getChildAt(i3);
            if (childAt != null) {
                if (i2 > 0) {
                    if (childAt.getBottom() < 0) {
                        removeAndRecycleView(childAt, recycler);
                        getChildCount();
                    }
                } else if (childAt.getTop() > getHeight()) {
                    removeAndRecycleView(childAt, recycler);
                    getChildCount();
                }
            }
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollHorizontally() {
        return this.scrollHorizontal;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollVertically() {
        return this.scrollVertical;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public RecyclerView.LayoutParams generateDefaultLayoutParams() {
        return new RecyclerView.LayoutParams(-2, -2);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (getItemCount() > 0 && !state.isPreLayout()) {
            detachAndScrapAttachedViews(recycler);
            int i2 = 0;
            for (int i3 = 0; i3 < getItemCount(); i3++) {
                View viewForPosition = recycler.getViewForPosition(i3);
                addView(viewForPosition);
                measureChildWithMargins(viewForPosition, 0, 0);
                int decoratedMeasuredWidth = getDecoratedMeasuredWidth(viewForPosition);
                int decoratedMeasuredHeight = getDecoratedMeasuredHeight(viewForPosition);
                if (this.scrollVertical) {
                    int i4 = i2 + decoratedMeasuredHeight;
                    layoutDecorated(viewForPosition, 0, i2, decoratedMeasuredWidth, i4);
                    i2 = i4;
                } else {
                    int i5 = i2 + decoratedMeasuredWidth;
                    layoutDecorated(viewForPosition, i2, 0, i5, decoratedMeasuredHeight);
                    i2 = i5;
                }
                if (this.scrollVertical) {
                    if (i2 > getHeight()) {
                        return;
                    }
                } else if (i2 > getWidth()) {
                    return;
                }
            }
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (this.scrollVertical) {
            return super.scrollHorizontallyBy(i2, recycler, state);
        }
        int fillHorizontal = fillHorizontal(i2, recycler, state);
        if (fillHorizontal == 0) {
            return 0;
        }
        offsetChildrenHorizontal(fillHorizontal * (-1));
        recyclerHorizontalHideView(i2, recycler, state);
        return fillHorizontal;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (!this.scrollVertical) {
            return super.scrollVerticallyBy(i2, recycler, state);
        }
        int fillVertical = fillVertical(i2, recycler, state);
        if (fillVertical == 0) {
            return 0;
        }
        offsetChildrenVertical(fillVertical * (-1));
        recyclerVerticalHideView(i2, recycler, state);
        return fillVertical;
    }

    public void setLooperEnable(boolean z) {
        this.looperEnable = z;
    }

    public void setScrollHorizontal(boolean z) {
        this.scrollHorizontal = z;
    }

    public void setScrollVertical(boolean z) {
        this.scrollVertical = z;
    }
}
