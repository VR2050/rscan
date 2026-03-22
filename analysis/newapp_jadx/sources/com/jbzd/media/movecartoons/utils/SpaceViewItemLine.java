package com.jbzd.media.movecartoons.utils;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* loaded from: classes2.dex */
public class SpaceViewItemLine extends RecyclerView.ItemDecoration {

    /* renamed from: a */
    public final int f10123a;

    /* renamed from: b */
    public boolean f10124b = true;

    /* renamed from: c */
    public boolean f10125c = true;

    public SpaceViewItemLine(int i2) {
        this.f10123a = i2;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, RecyclerView.State state) {
        int i2;
        int i3;
        int i4;
        int childAdapterPosition = recyclerView.getChildAdapterPosition(view);
        recyclerView.getAdapter();
        RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
        if (layoutManager instanceof StaggeredGridLayoutManager) {
            StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) layoutManager;
            i4 = staggeredGridLayoutManager.getOrientation();
            i3 = staggeredGridLayoutManager.getSpanCount();
            i2 = ((StaggeredGridLayoutManager.LayoutParams) view.getLayoutParams()).getSpanIndex();
        } else if (layoutManager instanceof GridLayoutManager) {
            GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
            i4 = gridLayoutManager.getOrientation();
            i3 = gridLayoutManager.getSpanCount();
            i2 = ((GridLayoutManager.LayoutParams) view.getLayoutParams()).getSpanIndex();
        } else if (layoutManager instanceof LinearLayoutManager) {
            i4 = ((LinearLayoutManager) layoutManager).getOrientation();
            i2 = 0;
            i3 = 1;
        } else {
            i2 = 0;
            i3 = 0;
            i4 = 0;
        }
        if (childAdapterPosition < 0 || childAdapterPosition >= recyclerView.getAdapter().getItemCount() - 0) {
            return;
        }
        if (i4 == 1) {
            float f2 = i3;
            float width = (recyclerView.getWidth() - (((this.f10124b ? 1 : -1) + i3) * this.f10123a)) / f2;
            float width2 = recyclerView.getWidth() / f2;
            int i5 = this.f10124b ? this.f10123a : 0;
            int i6 = this.f10123a;
            float f3 = i2;
            int i7 = (int) ((((i6 + width) * f3) + i5) - (f3 * width2));
            rect.left = i7;
            rect.right = (int) ((width2 - i7) - width);
            if (childAdapterPosition - 0 < i3 && this.f10125c) {
                rect.top = i6;
            }
            rect.bottom = i6;
            return;
        }
        float f4 = i3;
        float height = (recyclerView.getHeight() - (((this.f10124b ? 1 : -1) + i3) * this.f10123a)) / f4;
        float height2 = recyclerView.getHeight() / f4;
        int i8 = this.f10124b ? this.f10123a : 0;
        int i9 = this.f10123a;
        float f5 = i2;
        int i10 = (int) ((((i9 + height) * f5) + i8) - (f5 * height2));
        rect.bottom = i10;
        rect.top = (int) ((height2 - i10) - height);
        if (childAdapterPosition - 0 < i3 && this.f10125c) {
            rect.left = i9;
        }
        rect.right = i9;
    }
}
