package me.jingbin.library.stickyview;

import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import java.util.LinkedHashMap;
import java.util.Map;
import p448i.p452b.p453a.p454h.C4360a;
import p448i.p452b.p453a.p454h.C4364e;

/* loaded from: classes3.dex */
public class StickyLinearLayoutManager extends LinearLayoutManager {

    /* renamed from: c */
    public C4360a f12751c;

    /* renamed from: e */
    public C4364e f12752e;

    /* renamed from: k */
    public final Map<Integer, View> m5642k() {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        if (getChildCount() <= 0) {
            return linkedHashMap;
        }
        getPosition(getChildAt(0));
        throw null;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAttachedToWindow(RecyclerView recyclerView) {
        this.f12752e = new C4364e(recyclerView);
        C4360a c4360a = new C4360a(recyclerView);
        this.f12751c = c4360a;
        c4360a.f11266j = 0;
        throw null;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onDetachedFromWindow(RecyclerView recyclerView, RecyclerView.Recycler recycler) {
        C4360a c4360a = this.f12751c;
        if (c4360a != null) {
            c4360a.m4931c();
        }
        super.onDetachedFromWindow(recyclerView, recycler);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        super.onLayoutChildren(recycler, state);
        throw null;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void removeAndRecycleAllViews(RecyclerView.Recycler recycler) {
        super.removeAndRecycleAllViews(recycler);
        C4360a c4360a = this.f12751c;
        if (c4360a != null) {
            c4360a.m4932d();
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        C4360a c4360a;
        int scrollHorizontallyBy = super.scrollHorizontallyBy(i2, recycler, state);
        if (Math.abs(scrollHorizontallyBy) > 0 && (c4360a = this.f12751c) != null) {
            c4360a.m4936h(findFirstVisibleItemPosition(), m5642k(), this.f12752e, findFirstCompletelyVisibleItemPosition() == 0);
        }
        return scrollHorizontallyBy;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void scrollToPosition(int i2) {
        super.scrollToPositionWithOffset(i2, 0);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        C4360a c4360a;
        int scrollVerticallyBy = super.scrollVerticallyBy(i2, recycler, state);
        if (Math.abs(scrollVerticallyBy) > 0 && (c4360a = this.f12751c) != null) {
            c4360a.m4936h(findFirstVisibleItemPosition(), m5642k(), this.f12752e, findFirstCompletelyVisibleItemPosition() == 0);
        }
        return scrollVerticallyBy;
    }
}
