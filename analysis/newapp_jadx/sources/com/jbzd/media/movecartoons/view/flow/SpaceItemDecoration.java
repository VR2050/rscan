package com.jbzd.media.movecartoons.view.flow;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class SpaceItemDecoration extends RecyclerView.ItemDecoration {

    /* renamed from: h */
    private int f10145h;

    /* renamed from: v */
    private int f10146v;

    public SpaceItemDecoration(int i2, int i3) {
        this.f10145h = i2;
        this.f10146v = i3;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, RecyclerView.State state) {
        int i2 = this.f10146v;
        rect.top = i2;
        int i3 = this.f10145h;
        rect.left = i3;
        rect.right = i3;
        rect.bottom = i2;
    }
}
