package me.jingbin.library.decoration;

import android.graphics.Rect;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* loaded from: classes3.dex */
public class GridSpaceItemDecoration extends RecyclerView.ItemDecoration {

    /* renamed from: a */
    public int f12723a;

    /* renamed from: b */
    public int f12724b;

    /* renamed from: d */
    public int f12726d = 1;

    /* renamed from: e */
    public int f12727e = -1;

    /* renamed from: f */
    public int f12728f = 1;

    /* renamed from: c */
    public boolean f12725c = true;

    public GridSpaceItemDecoration(int i2) {
        this.f12724b = i2;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(@NonNull Rect rect, @NonNull View view, @NonNull RecyclerView recyclerView, @NonNull RecyclerView.State state) {
        boolean z;
        int i2;
        int i3;
        int itemCount = state.getItemCount() - 1;
        int childAdapterPosition = recyclerView.getChildAdapterPosition(view);
        if (childAdapterPosition < 0 || childAdapterPosition > itemCount - this.f12726d) {
            return;
        }
        RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
        boolean z2 = false;
        if (layoutManager instanceof GridLayoutManager) {
            GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
            GridLayoutManager.SpanSizeLookup spanSizeLookup = gridLayoutManager.getSpanSizeLookup();
            int spanCount = gridLayoutManager.getSpanCount();
            int spanSize = spanSizeLookup.getSpanSize(childAdapterPosition);
            this.f12728f = gridLayoutManager.getOrientation();
            this.f12723a = spanCount / spanSize;
            int spanIndex = spanSizeLookup.getSpanIndex(childAdapterPosition, spanCount) / spanSize;
            int spanGroupIndex = spanSizeLookup.getSpanGroupIndex(childAdapterPosition, spanCount) - 0;
            i3 = spanIndex;
            i2 = spanGroupIndex;
            z = false;
        } else if (layoutManager instanceof StaggeredGridLayoutManager) {
            StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) layoutManager;
            StaggeredGridLayoutManager.LayoutParams layoutParams = (StaggeredGridLayoutManager.LayoutParams) view.getLayoutParams();
            this.f12728f = staggeredGridLayoutManager.getOrientation();
            i3 = layoutParams.getSpanIndex();
            z = layoutParams.isFullSpan();
            this.f12723a = staggeredGridLayoutManager.getSpanCount();
            i2 = -1;
        } else {
            z = false;
            i2 = -1;
            i3 = 0;
        }
        int i4 = childAdapterPosition - 0;
        if (this.f12725c) {
            if (z) {
                rect.left = 0;
                rect.right = 0;
            } else if (this.f12728f == 1) {
                int i5 = this.f12724b;
                int i6 = this.f12723a;
                rect.left = i5 - ((i3 * i5) / i6);
                rect.right = ((i3 + 1) * i5) / i6;
            } else {
                int i7 = this.f12724b;
                int i8 = this.f12723a;
                rect.top = i7 - ((i3 * i7) / i8);
                rect.bottom = ((i3 + 1) * i7) / i8;
            }
            if (i2 <= -1) {
                if (this.f12727e == -1 && i4 < this.f12723a && z) {
                    this.f12727e = i4;
                }
                int i9 = this.f12727e;
                if ((i9 == -1 || i4 < i9) && i4 < this.f12723a) {
                    z2 = true;
                }
                if (z2) {
                    if (this.f12728f == 1) {
                        rect.top = this.f12724b;
                    } else {
                        rect.left = this.f12724b;
                    }
                }
            } else if (i2 < 1 && i4 < this.f12723a) {
                if (this.f12728f == 1) {
                    rect.top = this.f12724b;
                } else {
                    rect.left = this.f12724b;
                }
            }
            if (this.f12728f == 1) {
                rect.bottom = this.f12724b;
                return;
            } else {
                rect.right = this.f12724b;
                return;
            }
        }
        if (z) {
            rect.left = 0;
            rect.right = 0;
        } else if (this.f12728f == 1) {
            int i10 = this.f12724b;
            int i11 = this.f12723a;
            rect.left = (i3 * i10) / i11;
            rect.right = i10 - (((i3 + 1) * i10) / i11);
        } else {
            int i12 = this.f12724b;
            int i13 = this.f12723a;
            rect.top = (i3 * i12) / i13;
            rect.bottom = i12 - (((i3 + 1) * i12) / i13);
        }
        if (i2 > -1) {
            if (i2 >= 1) {
                if (this.f12728f == 1) {
                    rect.top = this.f12724b;
                    return;
                } else {
                    rect.left = this.f12724b;
                    return;
                }
            }
            return;
        }
        if (this.f12727e == -1 && i4 < this.f12723a && z) {
            this.f12727e = i4;
        }
        if (i4 >= this.f12723a || ((z && i4 != 0) || (this.f12727e != -1 && i4 != 0))) {
            z2 = true;
        }
        if (z2) {
            if (this.f12728f == 1) {
                rect.top = this.f12724b;
            } else {
                rect.left = this.f12724b;
            }
        }
    }
}
