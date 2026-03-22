package com.luck.picture.lib.widget;

import android.content.Context;
import android.util.AttributeSet;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.luck.picture.lib.listener.OnRecyclerViewPreloadMoreListener;

/* loaded from: classes2.dex */
public class RecyclerPreloadView extends RecyclerView {
    private static final int BOTTOM_DEFAULT = 1;
    public static final int BOTTOM_PRELOAD = 2;
    private static final String TAG = RecyclerPreloadView.class.getSimpleName();
    public boolean isEnabledLoadMore;
    public boolean isInTheBottom;
    private int mFirstVisiblePosition;
    private int mLastVisiblePosition;
    private OnRecyclerViewPreloadMoreListener onRecyclerViewPreloadListener;
    private int reachBottomRow;

    public RecyclerPreloadView(@NonNull Context context) {
        super(context);
        this.isInTheBottom = false;
        this.isEnabledLoadMore = false;
        this.reachBottomRow = 1;
    }

    public int getFirstVisiblePosition() {
        return this.mFirstVisiblePosition;
    }

    public int getLastVisiblePosition() {
        return this.mLastVisiblePosition;
    }

    public boolean isEnabledLoadMore() {
        return this.isEnabledLoadMore;
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void onScrollStateChanged(int i2) {
        super.onScrollStateChanged(i2);
        if (i2 == 0 || i2 == 1) {
            RecyclerView.LayoutManager layoutManager = getLayoutManager();
            if (layoutManager instanceof GridLayoutManager) {
                GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
                this.mFirstVisiblePosition = gridLayoutManager.findFirstVisibleItemPosition();
                this.mLastVisiblePosition = gridLayoutManager.findLastVisibleItemPosition();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x003e  */
    @Override // androidx.recyclerview.widget.RecyclerView
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onScrolled(int r5, int r6) {
        /*
            r4 = this;
            super.onScrolled(r5, r6)
            com.luck.picture.lib.listener.OnRecyclerViewPreloadMoreListener r5 = r4.onRecyclerViewPreloadListener
            if (r5 == 0) goto L61
            boolean r5 = r4.isEnabledLoadMore
            if (r5 == 0) goto L61
            androidx.recyclerview.widget.RecyclerView$LayoutManager r5 = r4.getLayoutManager()
            if (r5 == 0) goto L59
            androidx.recyclerview.widget.RecyclerView$Adapter r0 = r4.getAdapter()
            if (r0 == 0) goto L51
            boolean r1 = r5 instanceof androidx.recyclerview.widget.GridLayoutManager
            r2 = 1
            r3 = 0
            if (r1 == 0) goto L38
            androidx.recyclerview.widget.GridLayoutManager r5 = (androidx.recyclerview.widget.GridLayoutManager) r5
            int r0 = r0.getItemCount()
            int r1 = r5.getSpanCount()
            int r0 = r0 / r1
            int r1 = r5.findLastVisibleItemPosition()
            int r5 = r5.getSpanCount()
            int r1 = r1 / r5
            int r5 = r4.reachBottomRow
            int r0 = r0 - r5
            if (r1 < r0) goto L38
            r5 = 1
            goto L39
        L38:
            r5 = 0
        L39:
            if (r5 != 0) goto L3e
            r4.isInTheBottom = r3
            goto L61
        L3e:
            boolean r5 = r4.isInTheBottom
            if (r5 != 0) goto L4c
            com.luck.picture.lib.listener.OnRecyclerViewPreloadMoreListener r5 = r4.onRecyclerViewPreloadListener
            r5.onRecyclerViewPreloadMore()
            if (r6 <= 0) goto L61
            r4.isInTheBottom = r2
            goto L61
        L4c:
            if (r6 != 0) goto L61
            r4.isInTheBottom = r3
            goto L61
        L51:
            java.lang.RuntimeException r5 = new java.lang.RuntimeException
            java.lang.String r6 = "Adapter is null,Please check it!"
            r5.<init>(r6)
            throw r5
        L59:
            java.lang.RuntimeException r5 = new java.lang.RuntimeException
            java.lang.String r6 = "LayoutManager is null,Please check it!"
            r5.<init>(r6)
            throw r5
        L61:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.widget.RecyclerPreloadView.onScrolled(int, int):void");
    }

    public void setEnabledLoadMore(boolean z) {
        this.isEnabledLoadMore = z;
    }

    public void setOnRecyclerViewPreloadListener(OnRecyclerViewPreloadMoreListener onRecyclerViewPreloadMoreListener) {
        this.onRecyclerViewPreloadListener = onRecyclerViewPreloadMoreListener;
    }

    public void setReachBottomRow(int i2) {
        if (i2 < 1) {
            i2 = 1;
        }
        this.reachBottomRow = i2;
    }

    public RecyclerPreloadView(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.isInTheBottom = false;
        this.isEnabledLoadMore = false;
        this.reachBottomRow = 1;
    }

    public RecyclerPreloadView(@NonNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.isInTheBottom = false;
        this.isEnabledLoadMore = false;
        this.reachBottomRow = 1;
    }
}
