package me.jingbin.library.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.GridView;

/* loaded from: classes3.dex */
public class InGridView extends GridView {
    public InGridView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
    }

    @Override // android.widget.GridView, android.widget.AbsListView, android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, View.MeasureSpec.makeMeasureSpec(536870911, Integer.MIN_VALUE));
    }

    public InGridView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    public InGridView(Context context) {
        super(context);
    }
}
