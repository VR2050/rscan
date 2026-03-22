package me.jingbin.library.decoration;

import android.graphics.Rect;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* loaded from: classes3.dex */
public class GridDistanceScreenItemDecoration extends RecyclerView.ItemDecoration {

    /* renamed from: a */
    public int f12720a;

    /* renamed from: b */
    public int f12721b;

    /* renamed from: c */
    public int f12722c;

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(@NonNull Rect rect, @NonNull View view, @NonNull RecyclerView recyclerView, @NonNull RecyclerView.State state) {
        boolean z;
        int i2;
        int i3;
        int i4;
        int itemCount = state.getItemCount() - 1;
        int childAdapterPosition = recyclerView.getChildAdapterPosition(view);
        if (childAdapterPosition < 0 || childAdapterPosition > itemCount - 0) {
            return;
        }
        RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
        if (layoutManager instanceof GridLayoutManager) {
            GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
            GridLayoutManager.SpanSizeLookup spanSizeLookup = gridLayoutManager.getSpanSizeLookup();
            int spanCount = gridLayoutManager.getSpanCount();
            int spanSize = spanSizeLookup.getSpanSize(childAdapterPosition);
            this.f12721b = gridLayoutManager.getOrientation();
            this.f12720a = spanCount / spanSize;
            int spanIndex = spanSizeLookup.getSpanIndex(childAdapterPosition, spanCount) / spanSize;
            int spanGroupIndex = spanSizeLookup.getSpanGroupIndex(childAdapterPosition, spanCount) - 0;
            i3 = spanIndex;
            i2 = spanGroupIndex;
            z = false;
        } else if (layoutManager instanceof StaggeredGridLayoutManager) {
            StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) layoutManager;
            StaggeredGridLayoutManager.LayoutParams layoutParams = (StaggeredGridLayoutManager.LayoutParams) view.getLayoutParams();
            this.f12721b = staggeredGridLayoutManager.getOrientation();
            i3 = layoutParams.getSpanIndex();
            z = layoutParams.isFullSpan();
            this.f12720a = staggeredGridLayoutManager.getSpanCount();
            i2 = -1;
        } else {
            z = false;
            i2 = -1;
            i3 = 0;
        }
        int i5 = childAdapterPosition - 0;
        if (this.f12721b == 1) {
            if (z || (i4 = this.f12720a) == 1) {
                rect.left = 0;
                rect.right = 0;
                return;
            } else if (i3 == 0) {
                rect.left = 0;
                rect.right = 0;
                return;
            } else if (i3 == i4 - 1) {
                rect.left = 0;
                rect.right = 0;
                return;
            } else {
                rect.left = 0;
                rect.right = 0;
                return;
            }
        }
        if (z || this.f12720a == 1) {
            rect.left = 0;
        }
        if (i2 > -1) {
            if (i2 == 0) {
                rect.left = 0;
                return;
            }
            return;
        }
        if (this.f12722c == -1 && i5 < this.f12720a && z) {
            this.f12722c = i5;
        }
        int i6 = this.f12722c;
        if ((i6 == -1 || i5 < i6) && i5 < this.f12720a) {
            rect.left = 0;
        }
    }
}
