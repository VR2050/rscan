package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;

/* JADX INFO: loaded from: classes5.dex */
public class CommLayoutItemDecoration extends RecyclerView.ItemDecoration {
    private int margin;

    public CommLayoutItemDecoration(int spacingMargin) {
        this.margin = 0;
        this.margin = spacingMargin;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        outRect.set(0, 0, 0, this.margin);
    }
}
