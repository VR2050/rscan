package com.qunidayede.supportlibrary.utils;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.ColorRes;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import java.util.Objects;

/* loaded from: classes2.dex */
public class GridItemDecoration extends RecyclerView.ItemDecoration {

    /* renamed from: a */
    public Paint f10330a;

    /* renamed from: b */
    public Paint f10331b;

    /* renamed from: c */
    public C4053a f10332c;

    /* renamed from: com.qunidayede.supportlibrary.utils.GridItemDecoration$a */
    public static class C4053a {

        /* renamed from: a */
        public Context f10333a;

        /* renamed from: b */
        public int f10334b;

        /* renamed from: c */
        public int f10335c;

        /* renamed from: d */
        public int f10336d;

        /* renamed from: e */
        public int f10337e;

        /* renamed from: f */
        public boolean f10338f = false;

        /* renamed from: g */
        public boolean f10339g = false;

        /* renamed from: h */
        public boolean f10340h = false;

        public C4053a(Context context) {
            this.f10333a = context;
        }

        /* renamed from: a */
        public C4053a m4576a(@ColorRes int i2) {
            this.f10334b = this.f10333a.getResources().getColor(i2);
            this.f10335c = this.f10333a.getResources().getColor(i2);
            return this;
        }
    }

    public GridItemDecoration(C4053a c4053a) {
        this.f10332c = c4053a;
        Paint paint = new Paint(1);
        this.f10330a = paint;
        paint.setStyle(Paint.Style.FILL);
        this.f10330a.setColor(c4053a.f10335c);
        Paint paint2 = new Paint(1);
        this.f10331b = paint2;
        paint2.setStyle(Paint.Style.FILL);
        this.f10331b.setColor(c4053a.f10334b);
    }

    /* renamed from: a */
    public final int m4575a(RecyclerView recyclerView) {
        RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
        if (layoutManager instanceof GridLayoutManager) {
            return ((GridLayoutManager) layoutManager).getSpanCount();
        }
        if (layoutManager instanceof StaggeredGridLayoutManager) {
            return ((StaggeredGridLayoutManager) layoutManager).getSpanCount();
        }
        return -1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, RecyclerView.State state) {
        super.getItemOffsets(rect, view, recyclerView, state);
        int m4575a = m4575a(recyclerView);
        int itemCount = recyclerView.getAdapter().getItemCount();
        int viewLayoutPosition = ((RecyclerView.LayoutParams) view.getLayoutParams()).getViewLayoutPosition();
        C4053a c4053a = this.f10332c;
        if (c4053a.f10339g) {
            viewLayoutPosition--;
        }
        if (c4053a.f10340h && viewLayoutPosition == -1) {
            rect.set(0, 0, 0, c4053a.f10336d);
        }
        if (viewLayoutPosition < 0) {
            return;
        }
        int i2 = viewLayoutPosition % m4575a;
        int i3 = this.f10332c.f10337e;
        int i4 = (i2 * i3) / m4575a;
        boolean z = true;
        int i5 = i3 - (((i2 + 1) * i3) / m4575a);
        RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
        if (!(layoutManager instanceof GridLayoutManager) ? !(layoutManager instanceof StaggeredGridLayoutManager) || (((StaggeredGridLayoutManager) layoutManager).getOrientation() != 1 ? (viewLayoutPosition + 1) % m4575a != 0 : viewLayoutPosition < itemCount - (itemCount % m4575a)) : viewLayoutPosition < itemCount - (itemCount % m4575a)) {
            z = false;
        }
        rect.set(i4, 0, i5, (!z || this.f10332c.f10338f) ? this.f10332c.f10336d : 0);
        Objects.requireNonNull(this.f10332c);
        Objects.requireNonNull(this.f10332c);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(Canvas canvas, RecyclerView recyclerView, RecyclerView.State state) {
        super.onDraw(canvas, recyclerView, state);
        int childCount = recyclerView.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = recyclerView.getChildAt(i2);
            if (recyclerView.getChildViewHolder(childAt).getItemViewType() != 1 || this.f10332c.f10340h) {
                RecyclerView.LayoutParams layoutParams = (RecyclerView.LayoutParams) childAt.getLayoutParams();
                int left = childAt.getLeft() - ((ViewGroup.MarginLayoutParams) layoutParams).leftMargin;
                int right = childAt.getRight() + ((ViewGroup.MarginLayoutParams) layoutParams).rightMargin;
                canvas.drawRect(left, childAt.getBottom() + ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin, right, this.f10332c.f10336d + r2, this.f10331b);
            }
        }
        int childCount2 = recyclerView.getChildCount();
        for (int i3 = 0; i3 < childCount2; i3++) {
            View childAt2 = recyclerView.getChildAt(i3);
            if (recyclerView.getChildAdapterPosition(childAt2) % m4575a(recyclerView) != 0) {
                RecyclerView.LayoutParams layoutParams2 = (RecyclerView.LayoutParams) childAt2.getLayoutParams();
                int top = childAt2.getTop() - ((ViewGroup.MarginLayoutParams) layoutParams2).topMargin;
                int bottom = childAt2.getBottom() + ((ViewGroup.MarginLayoutParams) layoutParams2).bottomMargin + this.f10332c.f10336d;
                canvas.drawRect(childAt2.getRight() + ((ViewGroup.MarginLayoutParams) layoutParams2).rightMargin, top, this.f10332c.f10337e + r1, bottom, this.f10330a);
            }
        }
    }
}
