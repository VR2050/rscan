package com.jbzd.media.movecartoons.view.decoration;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class ItemDecorationH extends RecyclerView.ItemDecoration {
    private int padding;
    private int space;

    public ItemDecorationH(int i2) {
        this.padding = 0;
        this.space = i2;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, RecyclerView.State state) {
        RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
        if (recyclerView.getChildAdapterPosition(view) == 0) {
            rect.set(this.padding, 0, this.space, 0);
        } else if (recyclerView.getChildAdapterPosition(view) == layoutManager.getItemCount() - 1) {
            rect.set(0, 0, this.padding, 0);
        } else {
            rect.set(0, 0, this.space, 0);
        }
    }

    public ItemDecorationH(int i2, int i3) {
        this.padding = 0;
        this.space = i2;
        this.padding = i3;
    }
}
