package com.jbzd.media.movecartoons.view.decoration;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* loaded from: classes2.dex */
public class WaterfallItemDecoration extends RecyclerView.ItemDecoration {
    private int space;

    public WaterfallItemDecoration(int i2) {
        this.space = i2;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, RecyclerView.State state) {
        StaggeredGridLayoutManager.LayoutParams layoutParams = (StaggeredGridLayoutManager.LayoutParams) view.getLayoutParams();
        int i2 = this.space;
        rect.top = i2 / 2;
        rect.bottom = i2 / 2;
        if (layoutParams.getSpanIndex() == 0) {
            int i3 = this.space;
            rect.left = i3;
            rect.right = i3 / 2;
        } else if (layoutParams.getSpanIndex() == 1) {
            int i4 = this.space;
            rect.left = i4 / 2;
            rect.right = i4;
        }
    }
}
