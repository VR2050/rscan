package im.uwrkaxlmjj.ui.components.recyclerview;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;

/* JADX INFO: loaded from: classes5.dex */
public class FullRecyclerView extends RecyclerView {
    public FullRecyclerView(Context context) {
        super(context, null);
    }

    public FullRecyclerView(Context context, AttributeSet attrs) {
        super(context, attrs, 0);
    }

    public FullRecyclerView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int expandSpec = View.MeasureSpec.makeMeasureSpec(536870911, Integer.MIN_VALUE);
        super.onMeasure(widthMeasureSpec, expandSpec);
    }
}
