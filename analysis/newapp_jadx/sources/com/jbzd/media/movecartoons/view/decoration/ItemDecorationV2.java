package com.jbzd.media.movecartoons.view.decoration;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class ItemDecorationV2 extends RecyclerView.ItemDecoration {
    private int mPadding;
    private int space;

    public ItemDecorationV2(int i2) {
        this.space = i2;
        this.mPadding = 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, RecyclerView.State state) {
        if (recyclerView.getChildAdapterPosition(view) == recyclerView.getLayoutManager().getItemCount() - 1) {
            rect.set(0, 0, 0, this.mPadding);
        } else if (recyclerView.getChildAdapterPosition(view) == 0) {
            rect.set(0, this.mPadding, 0, this.space);
        } else {
            rect.set(0, 0, 0, this.space);
        }
    }

    public ItemDecorationV2(int i2, int i3) {
        this.space = i2;
        this.mPadding = i3;
    }
}
