package im.uwrkaxlmjj.ui.hui.decoration;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class TopDecorationWithSearch extends RecyclerView.ItemDecoration {
    private boolean isGridLayoutManager;
    private int top;

    public TopDecorationWithSearch() {
        this.isGridLayoutManager = false;
        this.top = AndroidUtilities.dp(55.0f);
    }

    public TopDecorationWithSearch(int top, boolean isGridLayoutManager) {
        this.isGridLayoutManager = false;
        this.top = AndroidUtilities.dp(top);
        this.isGridLayoutManager = isGridLayoutManager;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        super.getItemOffsets(outRect, view, parent, state);
        int position = parent.getChildAdapterPosition(view);
        if (position == 0) {
            outRect.top = this.top;
        }
        if (this.isGridLayoutManager && position == 1) {
            outRect.top = this.top;
        }
    }
}
