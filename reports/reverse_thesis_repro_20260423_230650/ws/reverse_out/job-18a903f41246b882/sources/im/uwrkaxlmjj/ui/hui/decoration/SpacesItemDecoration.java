package im.uwrkaxlmjj.ui.hui.decoration;

import android.content.Context;
import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;

/* JADX INFO: loaded from: classes5.dex */
public class SpacesItemDecoration extends RecyclerView.ItemDecoration {
    private Context context;
    private int space;

    public SpacesItemDecoration(int space, Context context) {
        this.space = space;
        this.context = context;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        if (parent.getChildPosition(view) != 0) {
            outRect.top = this.space;
        }
    }
}
