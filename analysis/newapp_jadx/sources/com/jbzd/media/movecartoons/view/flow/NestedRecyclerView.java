package com.jbzd.media.movecartoons.view.flow;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class NestedRecyclerView extends RecyclerView {
    public NestedRecyclerView(Context context) {
        super(context);
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        FlowLayoutManager flowLayoutManager = (FlowLayoutManager) getLayoutManager();
        int mode = View.MeasureSpec.getMode(i2);
        int size = View.MeasureSpec.getSize(i2);
        int mode2 = View.MeasureSpec.getMode(i3);
        int size2 = View.MeasureSpec.getSize(i3);
        if (mode != 1073741824) {
            size = getContext().getResources().getDisplayMetrics().widthPixels;
        }
        if (mode2 != 1073741824) {
            size2 = getPaddingBottom() + getPaddingTop() + flowLayoutManager.getTotalHeight();
        }
        setMeasuredDimension(size, size2);
    }

    public NestedRecyclerView(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    public NestedRecyclerView(Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
    }
}
