package com.drake.brv.layoutmanager;

import android.content.Context;
import android.graphics.PointF;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.listener.OnHoverAttachListener;
import com.drake.brv.listener.SnapLinearSmoothScroller;
import java.util.ArrayList;
import java.util.List;
import p005b.p177i.p178a.p182j.ViewTreeObserverOnGlobalLayoutListenerC1859b;

/* loaded from: classes.dex */
public class HoverLinearLayoutManager extends LinearLayoutManager {

    /* renamed from: c */
    public BindingAdapter f8985c;

    /* renamed from: e */
    public List<Integer> f8986e;

    /* renamed from: f */
    public RecyclerView.AdapterDataObserver f8987f;

    /* renamed from: g */
    public View f8988g;

    /* renamed from: h */
    public int f8989h;

    /* renamed from: i */
    public int f8990i;

    /* renamed from: j */
    public int f8991j;

    /* renamed from: k */
    public boolean f8992k;

    /* renamed from: l */
    public int f8993l;

    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new C3244a();

        /* renamed from: c */
        public Parcelable f8994c;

        /* renamed from: e */
        public int f8995e;

        /* renamed from: f */
        public int f8996f;

        /* renamed from: com.drake.brv.layoutmanager.HoverLinearLayoutManager$SavedState$a */
        public class C3244a implements Parcelable.Creator<SavedState> {
            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel parcel) {
                return new SavedState(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int i2) {
                return new SavedState[i2];
            }
        }

        public SavedState() {
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(@NonNull Parcel parcel, int i2) {
            parcel.writeParcelable(this.f8994c, i2);
            parcel.writeInt(this.f8995e);
            parcel.writeInt(this.f8996f);
        }

        public SavedState(Parcel parcel) {
            this.f8994c = parcel.readParcelable(SavedState.class.getClassLoader());
            this.f8995e = parcel.readInt();
            this.f8996f = parcel.readInt();
        }
    }

    /* renamed from: com.drake.brv.layoutmanager.HoverLinearLayoutManager$a */
    public class C3245a extends RecyclerView.AdapterDataObserver {
        public C3245a(ViewTreeObserverOnGlobalLayoutListenerC1859b viewTreeObserverOnGlobalLayoutListenerC1859b) {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onChanged() {
            HoverLinearLayoutManager.this.f8986e.clear();
            int itemCount = HoverLinearLayoutManager.this.f8985c.getItemCount();
            for (int i2 = 0; i2 < itemCount; i2++) {
                if (HoverLinearLayoutManager.this.f8985c.m3934k(i2)) {
                    HoverLinearLayoutManager.this.f8986e.add(Integer.valueOf(i2));
                }
            }
            HoverLinearLayoutManager hoverLinearLayoutManager = HoverLinearLayoutManager.this;
            if (hoverLinearLayoutManager.f8988g == null || hoverLinearLayoutManager.f8986e.contains(Integer.valueOf(hoverLinearLayoutManager.f8989h))) {
                return;
            }
            HoverLinearLayoutManager.this.m3975q(null);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeInserted(int i2, int i3) {
            int size = HoverLinearLayoutManager.this.f8986e.size();
            if (size > 0) {
                for (int m3969k = HoverLinearLayoutManager.m3969k(HoverLinearLayoutManager.this, i2); m3969k != -1 && m3969k < size; m3969k++) {
                    List<Integer> list = HoverLinearLayoutManager.this.f8986e;
                    list.set(m3969k, Integer.valueOf(list.get(m3969k).intValue() + i3));
                }
            }
            for (int i4 = i2; i4 < i2 + i3; i4++) {
                if (HoverLinearLayoutManager.this.f8985c.m3934k(i4)) {
                    int m3969k2 = HoverLinearLayoutManager.m3969k(HoverLinearLayoutManager.this, i4);
                    if (m3969k2 != -1) {
                        HoverLinearLayoutManager.this.f8986e.add(m3969k2, Integer.valueOf(i4));
                    } else {
                        HoverLinearLayoutManager.this.f8986e.add(Integer.valueOf(i4));
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeMoved(int i2, int i3, int i4) {
            int i5;
            int size = HoverLinearLayoutManager.this.f8986e.size();
            if (size > 0) {
                for (int m3969k = HoverLinearLayoutManager.m3969k(HoverLinearLayoutManager.this, Math.min(i2, i3)); m3969k != -1 && m3969k < size; m3969k++) {
                    int intValue = HoverLinearLayoutManager.this.f8986e.get(m3969k).intValue();
                    if (intValue >= i2 && intValue < i2 + i4) {
                        i5 = (i3 - i2) + intValue;
                    } else if (i2 < i3 && intValue >= i2 + i4 && intValue <= i3) {
                        i5 = intValue - i4;
                    } else if (i2 <= i3 || intValue < i3 || intValue > i2) {
                        return;
                    } else {
                        i5 = intValue + i4;
                    }
                    if (i5 == intValue) {
                        return;
                    }
                    HoverLinearLayoutManager.this.f8986e.set(m3969k, Integer.valueOf(i5));
                    int intValue2 = HoverLinearLayoutManager.this.f8986e.remove(m3969k).intValue();
                    int m3969k2 = HoverLinearLayoutManager.m3969k(HoverLinearLayoutManager.this, intValue2);
                    if (m3969k2 != -1) {
                        HoverLinearLayoutManager.this.f8986e.add(m3969k2, Integer.valueOf(intValue2));
                    } else {
                        HoverLinearLayoutManager.this.f8986e.add(Integer.valueOf(intValue2));
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeRemoved(int i2, int i3) {
            int size = HoverLinearLayoutManager.this.f8986e.size();
            if (size > 0) {
                int i4 = i2 + i3;
                for (int i5 = i4 - 1; i5 >= i2; i5--) {
                    int m3972n = HoverLinearLayoutManager.this.m3972n(i5);
                    if (m3972n != -1) {
                        HoverLinearLayoutManager.this.f8986e.remove(m3972n);
                        size--;
                    }
                }
                HoverLinearLayoutManager hoverLinearLayoutManager = HoverLinearLayoutManager.this;
                if (hoverLinearLayoutManager.f8988g != null && !hoverLinearLayoutManager.f8986e.contains(Integer.valueOf(hoverLinearLayoutManager.f8989h))) {
                    HoverLinearLayoutManager.this.m3975q(null);
                }
                for (int m3969k = HoverLinearLayoutManager.m3969k(HoverLinearLayoutManager.this, i4); m3969k != -1 && m3969k < size; m3969k++) {
                    List<Integer> list = HoverLinearLayoutManager.this.f8986e;
                    list.set(m3969k, Integer.valueOf(list.get(m3969k).intValue() - i3));
                }
            }
        }
    }

    public HoverLinearLayoutManager(Context context, int i2, boolean z) {
        super(context, i2, z);
        this.f8986e = new ArrayList(0);
        this.f8987f = new C3245a(null);
        this.f8989h = -1;
        this.f8990i = -1;
        this.f8991j = 0;
        this.f8992k = true;
        this.f8993l = 0;
    }

    /* renamed from: k */
    public static int m3969k(HoverLinearLayoutManager hoverLinearLayoutManager, int i2) {
        int size = hoverLinearLayoutManager.f8986e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (i4 > 0) {
                int i5 = i4 - 1;
                if (hoverLinearLayoutManager.f8986e.get(i5).intValue() >= i2) {
                    size = i5;
                }
            }
            if (hoverLinearLayoutManager.f8986e.get(i4).intValue() >= i2) {
                return i4;
            }
            i3 = i4 + 1;
        }
        return -1;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollHorizontally() {
        return super.canScrollHorizontally() && this.f8992k;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollVertically() {
        return super.canScrollVertically() && this.f8992k;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollExtent(RecyclerView.State state) {
        m3971m();
        int computeHorizontalScrollExtent = super.computeHorizontalScrollExtent(state);
        m3970l();
        return computeHorizontalScrollExtent;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollOffset(RecyclerView.State state) {
        m3971m();
        int computeHorizontalScrollOffset = super.computeHorizontalScrollOffset(state);
        m3970l();
        return computeHorizontalScrollOffset;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollRange(RecyclerView.State state) {
        m3971m();
        int computeHorizontalScrollRange = super.computeHorizontalScrollRange(state);
        m3970l();
        return computeHorizontalScrollRange;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.SmoothScroller.ScrollVectorProvider
    public PointF computeScrollVectorForPosition(int i2) {
        m3971m();
        PointF computeScrollVectorForPosition = super.computeScrollVectorForPosition(i2);
        m3970l();
        return computeScrollVectorForPosition;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollExtent(RecyclerView.State state) {
        m3971m();
        int computeVerticalScrollExtent = super.computeVerticalScrollExtent(state);
        m3970l();
        return computeVerticalScrollExtent;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollOffset(RecyclerView.State state) {
        m3971m();
        int computeVerticalScrollOffset = super.computeVerticalScrollOffset(state);
        m3970l();
        return computeVerticalScrollOffset;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollRange(RecyclerView.State state) {
        m3971m();
        int computeVerticalScrollRange = super.computeVerticalScrollRange(state);
        m3970l();
        return computeVerticalScrollRange;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public int findFirstCompletelyVisibleItemPosition() {
        m3971m();
        int findFirstCompletelyVisibleItemPosition = super.findFirstCompletelyVisibleItemPosition();
        m3970l();
        return findFirstCompletelyVisibleItemPosition;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public int findFirstVisibleItemPosition() {
        m3971m();
        int findFirstVisibleItemPosition = super.findFirstVisibleItemPosition();
        m3970l();
        return findFirstVisibleItemPosition;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public int findLastCompletelyVisibleItemPosition() {
        m3971m();
        int findLastCompletelyVisibleItemPosition = super.findLastCompletelyVisibleItemPosition();
        m3970l();
        return findLastCompletelyVisibleItemPosition;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public int findLastVisibleItemPosition() {
        m3971m();
        int findLastVisibleItemPosition = super.findLastVisibleItemPosition();
        m3970l();
        return findLastVisibleItemPosition;
    }

    /* renamed from: l */
    public final void m3970l() {
        View view;
        int i2 = this.f8993l + 1;
        this.f8993l = i2;
        if (i2 != 1 || (view = this.f8988g) == null) {
            return;
        }
        attachView(view);
    }

    /* renamed from: m */
    public final void m3971m() {
        View view;
        int i2 = this.f8993l - 1;
        this.f8993l = i2;
        if (i2 != 0 || (view = this.f8988g) == null) {
            return;
        }
        detachView(view);
    }

    /* renamed from: n */
    public final int m3972n(int i2) {
        int size = this.f8986e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (this.f8986e.get(i4).intValue() > i2) {
                size = i4 - 1;
            } else {
                if (this.f8986e.get(i4).intValue() >= i2) {
                    return i4;
                }
                i3 = i4 + 1;
            }
        }
        return -1;
    }

    /* renamed from: o */
    public final int m3973o(int i2) {
        int size = this.f8986e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (this.f8986e.get(i4).intValue() <= i2) {
                if (i4 < this.f8986e.size() - 1) {
                    int i5 = i4 + 1;
                    if (this.f8986e.get(i5).intValue() <= i2) {
                        i3 = i5;
                    }
                }
                return i4;
            }
            size = i4 - 1;
        }
        return -1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAdapterChanged(RecyclerView.Adapter adapter, RecyclerView.Adapter adapter2) {
        super.onAdapterChanged(adapter, adapter2);
        m3976r(adapter2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAttachedToWindow(RecyclerView recyclerView) {
        super.onAttachedToWindow(recyclerView);
        m3976r(recyclerView.getAdapter());
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public View onFocusSearchFailed(View view, int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3971m();
        View onFocusSearchFailed = super.onFocusSearchFailed(view, i2, recycler, state);
        m3970l();
        return onFocusSearchFailed;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3971m();
        super.onLayoutChildren(recycler, state);
        m3970l();
        if (state.isPreLayout()) {
            return;
        }
        m3977s(recycler, true);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof SavedState) {
            SavedState savedState = (SavedState) parcelable;
            this.f8990i = savedState.f8995e;
            this.f8991j = savedState.f8996f;
            parcelable = savedState.f8994c;
        }
        super.onRestoreInstanceState(parcelable);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState();
        savedState.f8994c = super.onSaveInstanceState();
        savedState.f8995e = this.f8990i;
        savedState.f8996f = this.f8991j;
        return savedState;
    }

    /* renamed from: p */
    public final void m3974p(View view) {
        measureChildWithMargins(view, 0, 0);
        if (getOrientation() == 1) {
            view.layout(getPaddingLeft(), 0, getWidth() - getPaddingRight(), view.getMeasuredHeight());
        } else {
            view.layout(0, getPaddingTop(), view.getMeasuredWidth(), getHeight() - getPaddingBottom());
        }
    }

    /* renamed from: q */
    public final void m3975q(@Nullable RecyclerView.Recycler recycler) {
        View view = this.f8988g;
        this.f8988g = null;
        this.f8989h = -1;
        view.setTranslationX(0.0f);
        view.setTranslationY(0.0f);
        OnHoverAttachListener onHoverAttachListener = this.f8985c.f8900B;
        if (onHoverAttachListener != null) {
            onHoverAttachListener.m1208b(view);
        }
        stopIgnoringView(view);
        removeView(view);
        if (recycler != null) {
            recycler.recycleView(view);
        }
    }

    /* renamed from: r */
    public final void m3976r(RecyclerView.Adapter adapter) {
        BindingAdapter bindingAdapter = this.f8985c;
        if (bindingAdapter != null) {
            bindingAdapter.unregisterAdapterDataObserver(this.f8987f);
        }
        if (!(adapter instanceof BindingAdapter)) {
            this.f8985c = null;
            this.f8986e.clear();
        } else {
            BindingAdapter bindingAdapter2 = (BindingAdapter) adapter;
            this.f8985c = bindingAdapter2;
            bindingAdapter2.registerAdapterDataObserver(this.f8987f);
            this.f8987f.onChanged();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:114:0x005c, code lost:
    
        if ((r8.getBottom() - r8.getTranslationY()) >= 0.0f) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x0077, code lost:
    
        if ((r8.getTranslationX() + r8.getLeft()) <= (getWidth() + 0.0f)) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x0086, code lost:
    
        if ((r8.getRight() - r8.getTranslationX()) >= 0.0f) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x004a, code lost:
    
        if ((r8.getTranslationY() + r8.getTop()) <= (getHeight() + 0.0f)) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x004c, code lost:
    
        r10 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00e2, code lost:
    
        if ((r8.getBottom() - r8.getTranslationY()) > (getHeight() + 0.0f)) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00e4, code lost:
    
        r8 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0121, code lost:
    
        if (r8 != false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00e6, code lost:
    
        r8 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00f4, code lost:
    
        if ((r8.getTranslationY() + r8.getTop()) < 0.0f) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x010f, code lost:
    
        if ((r8.getRight() - r8.getTranslationX()) > (getWidth() + 0.0f)) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x011e, code lost:
    
        if ((r8.getTranslationX() + r8.getLeft()) < 0.0f) goto L53;
     */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0090 A[LOOP:0: B:5:0x0010->B:19:0x0090, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x008b A[SYNTHETIC] */
    /* renamed from: s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3977s(androidx.recyclerview.widget.RecyclerView.Recycler r13, boolean r14) {
        /*
            Method dump skipped, instructions count: 605
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.drake.brv.layoutmanager.HoverLinearLayoutManager.m3977s(androidx.recyclerview.widget.RecyclerView$Recycler, boolean):void");
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3971m();
        int scrollHorizontallyBy = super.scrollHorizontallyBy(i2, recycler, state);
        m3970l();
        if (scrollHorizontallyBy != 0) {
            m3977s(recycler, false);
        }
        return scrollHorizontallyBy;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void scrollToPosition(int i2) {
        scrollToPositionWithOffset(i2, Integer.MIN_VALUE);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public void scrollToPositionWithOffset(int i2, int i3) {
        this.f8990i = -1;
        this.f8991j = Integer.MIN_VALUE;
        int m3973o = m3973o(i2);
        if (m3973o == -1 || m3972n(i2) != -1) {
            super.scrollToPositionWithOffset(i2, i3);
            return;
        }
        int i4 = i2 - 1;
        if (m3972n(i4) != -1) {
            super.scrollToPositionWithOffset(i4, i3);
            return;
        }
        if (this.f8988g == null || m3973o != m3972n(this.f8989h)) {
            this.f8990i = i2;
            this.f8991j = i3;
            super.scrollToPositionWithOffset(i2, i3);
        } else {
            if (i3 == Integer.MIN_VALUE) {
                i3 = 0;
            }
            super.scrollToPositionWithOffset(i2, this.f8988g.getHeight() + i3);
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3971m();
        int scrollVerticallyBy = super.scrollVerticallyBy(i2, recycler, state);
        m3970l();
        if (scrollVerticallyBy != 0) {
            m3977s(recycler, false);
        }
        return scrollVerticallyBy;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void smoothScrollToPosition(RecyclerView recyclerView, RecyclerView.State state, int i2) {
        SnapLinearSmoothScroller snapLinearSmoothScroller = new SnapLinearSmoothScroller(recyclerView.getContext());
        snapLinearSmoothScroller.setTargetPosition(i2);
        startSmoothScroll(snapLinearSmoothScroller);
    }

    public HoverLinearLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        super(context, attributeSet, i2, i3);
        this.f8986e = new ArrayList(0);
        this.f8987f = new C3245a(null);
        this.f8989h = -1;
        this.f8990i = -1;
        this.f8991j = 0;
        this.f8992k = true;
        this.f8993l = 0;
    }
}
