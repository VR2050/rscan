package com.drake.brv.layoutmanager;

import android.content.Context;
import android.graphics.PointF;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import com.drake.brv.BindingAdapter;
import com.drake.brv.listener.OnHoverAttachListener;
import java.util.ArrayList;
import java.util.List;
import p005b.p177i.p178a.p182j.ViewTreeObserverOnGlobalLayoutListenerC1860c;

/* loaded from: classes.dex */
public class HoverStaggeredGridLayoutManager extends StaggeredGridLayoutManager {

    /* renamed from: c */
    public BindingAdapter f8998c;

    /* renamed from: e */
    public List<Integer> f8999e;

    /* renamed from: f */
    public RecyclerView.AdapterDataObserver f9000f;

    /* renamed from: g */
    public View f9001g;

    /* renamed from: h */
    public int f9002h;

    /* renamed from: i */
    public int f9003i;

    /* renamed from: j */
    public int f9004j;

    /* renamed from: k */
    public boolean f9005k;

    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new C3246a();

        /* renamed from: c */
        public Parcelable f9006c;

        /* renamed from: e */
        public int f9007e;

        /* renamed from: f */
        public int f9008f;

        /* renamed from: com.drake.brv.layoutmanager.HoverStaggeredGridLayoutManager$SavedState$a */
        public class C3246a implements Parcelable.Creator<SavedState> {
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
            parcel.writeParcelable(this.f9006c, i2);
            parcel.writeInt(this.f9007e);
            parcel.writeInt(this.f9008f);
        }

        public SavedState(Parcel parcel) {
            this.f9006c = parcel.readParcelable(SavedState.class.getClassLoader());
            this.f9007e = parcel.readInt();
            this.f9008f = parcel.readInt();
        }
    }

    /* renamed from: com.drake.brv.layoutmanager.HoverStaggeredGridLayoutManager$a */
    public class C3247a extends RecyclerView.AdapterDataObserver {
        public C3247a(ViewTreeObserverOnGlobalLayoutListenerC1860c viewTreeObserverOnGlobalLayoutListenerC1860c) {
        }

        /* renamed from: a */
        public final void m3987a(int i2) {
            int intValue = HoverStaggeredGridLayoutManager.this.f8999e.remove(i2).intValue();
            int m3978k = HoverStaggeredGridLayoutManager.m3978k(HoverStaggeredGridLayoutManager.this, intValue);
            if (m3978k != -1) {
                HoverStaggeredGridLayoutManager.this.f8999e.add(m3978k, Integer.valueOf(intValue));
            } else {
                HoverStaggeredGridLayoutManager.this.f8999e.add(Integer.valueOf(intValue));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onChanged() {
            HoverStaggeredGridLayoutManager.this.f8999e.clear();
            int itemCount = HoverStaggeredGridLayoutManager.this.f8998c.getItemCount();
            for (int i2 = 0; i2 < itemCount; i2++) {
                if (HoverStaggeredGridLayoutManager.this.f8998c.m3934k(i2)) {
                    HoverStaggeredGridLayoutManager.this.f8999e.add(Integer.valueOf(i2));
                }
            }
            HoverStaggeredGridLayoutManager hoverStaggeredGridLayoutManager = HoverStaggeredGridLayoutManager.this;
            if (hoverStaggeredGridLayoutManager.f9001g == null || hoverStaggeredGridLayoutManager.f8999e.contains(Integer.valueOf(hoverStaggeredGridLayoutManager.f9002h))) {
                return;
            }
            HoverStaggeredGridLayoutManager.this.m3984q(null);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeInserted(int i2, int i3) {
            int size = HoverStaggeredGridLayoutManager.this.f8999e.size();
            if (size > 0) {
                for (int m3978k = HoverStaggeredGridLayoutManager.m3978k(HoverStaggeredGridLayoutManager.this, i2); m3978k != -1 && m3978k < size; m3978k++) {
                    List<Integer> list = HoverStaggeredGridLayoutManager.this.f8999e;
                    list.set(m3978k, Integer.valueOf(list.get(m3978k).intValue() + i3));
                }
            }
            for (int i4 = i2; i4 < i2 + i3; i4++) {
                if (HoverStaggeredGridLayoutManager.this.f8998c.m3934k(i4)) {
                    int m3978k2 = HoverStaggeredGridLayoutManager.m3978k(HoverStaggeredGridLayoutManager.this, i4);
                    if (m3978k2 != -1) {
                        HoverStaggeredGridLayoutManager.this.f8999e.add(m3978k2, Integer.valueOf(i4));
                    } else {
                        HoverStaggeredGridLayoutManager.this.f8999e.add(Integer.valueOf(i4));
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeMoved(int i2, int i3, int i4) {
            int size = HoverStaggeredGridLayoutManager.this.f8999e.size();
            if (size > 0) {
                if (i2 < i3) {
                    for (int m3978k = HoverStaggeredGridLayoutManager.m3978k(HoverStaggeredGridLayoutManager.this, i2); m3978k != -1 && m3978k < size; m3978k++) {
                        int intValue = HoverStaggeredGridLayoutManager.this.f8999e.get(m3978k).intValue();
                        if (intValue >= i2 && intValue < i2 + i4) {
                            HoverStaggeredGridLayoutManager.this.f8999e.set(m3978k, Integer.valueOf(intValue - (i3 - i2)));
                            m3987a(m3978k);
                        } else {
                            if (intValue < i2 + i4 || intValue > i3) {
                                return;
                            }
                            HoverStaggeredGridLayoutManager.this.f8999e.set(m3978k, Integer.valueOf(intValue - i4));
                            m3987a(m3978k);
                        }
                    }
                    return;
                }
                for (int m3978k2 = HoverStaggeredGridLayoutManager.m3978k(HoverStaggeredGridLayoutManager.this, i3); m3978k2 != -1 && m3978k2 < size; m3978k2++) {
                    int intValue2 = HoverStaggeredGridLayoutManager.this.f8999e.get(m3978k2).intValue();
                    if (intValue2 >= i2 && intValue2 < i2 + i4) {
                        HoverStaggeredGridLayoutManager.this.f8999e.set(m3978k2, Integer.valueOf((i3 - i2) + intValue2));
                        m3987a(m3978k2);
                    } else {
                        if (intValue2 < i3 || intValue2 > i2) {
                            return;
                        }
                        HoverStaggeredGridLayoutManager.this.f8999e.set(m3978k2, Integer.valueOf(intValue2 + i4));
                        m3987a(m3978k2);
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeRemoved(int i2, int i3) {
            int size = HoverStaggeredGridLayoutManager.this.f8999e.size();
            if (size > 0) {
                int i4 = i2 + i3;
                for (int i5 = i4 - 1; i5 >= i2; i5--) {
                    int m3981n = HoverStaggeredGridLayoutManager.this.m3981n(i5);
                    if (m3981n != -1) {
                        HoverStaggeredGridLayoutManager.this.f8999e.remove(m3981n);
                        size--;
                    }
                }
                HoverStaggeredGridLayoutManager hoverStaggeredGridLayoutManager = HoverStaggeredGridLayoutManager.this;
                if (hoverStaggeredGridLayoutManager.f9001g != null && !hoverStaggeredGridLayoutManager.f8999e.contains(Integer.valueOf(hoverStaggeredGridLayoutManager.f9002h))) {
                    HoverStaggeredGridLayoutManager.this.m3984q(null);
                }
                for (int m3978k = HoverStaggeredGridLayoutManager.m3978k(HoverStaggeredGridLayoutManager.this, i4); m3978k != -1 && m3978k < size; m3978k++) {
                    List<Integer> list = HoverStaggeredGridLayoutManager.this.f8999e;
                    list.set(m3978k, Integer.valueOf(list.get(m3978k).intValue() - i3));
                }
            }
        }
    }

    public HoverStaggeredGridLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        super(context, attributeSet, i2, i3);
        this.f8999e = new ArrayList(0);
        this.f9000f = new C3247a(null);
        this.f9002h = -1;
        this.f9003i = -1;
        this.f9004j = 0;
        this.f9005k = true;
    }

    /* renamed from: k */
    public static int m3978k(HoverStaggeredGridLayoutManager hoverStaggeredGridLayoutManager, int i2) {
        int size = hoverStaggeredGridLayoutManager.f8999e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (i4 > 0) {
                int i5 = i4 - 1;
                if (hoverStaggeredGridLayoutManager.f8999e.get(i5).intValue() >= i2) {
                    size = i5;
                }
            }
            if (hoverStaggeredGridLayoutManager.f8999e.get(i4).intValue() >= i2) {
                return i4;
            }
            i3 = i4 + 1;
        }
        return -1;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollHorizontally() {
        return super.canScrollHorizontally() && this.f9005k;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollVertically() {
        return super.canScrollVertically() && this.f9005k;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollExtent(RecyclerView.State state) {
        m3980m();
        int computeHorizontalScrollExtent = super.computeHorizontalScrollExtent(state);
        m3979l();
        return computeHorizontalScrollExtent;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollOffset(RecyclerView.State state) {
        m3980m();
        int computeHorizontalScrollOffset = super.computeHorizontalScrollOffset(state);
        m3979l();
        return computeHorizontalScrollOffset;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollRange(RecyclerView.State state) {
        m3980m();
        int computeHorizontalScrollRange = super.computeHorizontalScrollRange(state);
        m3979l();
        return computeHorizontalScrollRange;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.SmoothScroller.ScrollVectorProvider
    public PointF computeScrollVectorForPosition(int i2) {
        m3980m();
        PointF computeScrollVectorForPosition = super.computeScrollVectorForPosition(i2);
        m3979l();
        return computeScrollVectorForPosition;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollExtent(RecyclerView.State state) {
        m3980m();
        int computeVerticalScrollExtent = super.computeVerticalScrollExtent(state);
        m3979l();
        return computeVerticalScrollExtent;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollOffset(RecyclerView.State state) {
        m3980m();
        int computeVerticalScrollOffset = super.computeVerticalScrollOffset(state);
        m3979l();
        return computeVerticalScrollOffset;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollRange(RecyclerView.State state) {
        m3980m();
        int computeVerticalScrollRange = super.computeVerticalScrollRange(state);
        m3979l();
        return computeVerticalScrollRange;
    }

    /* renamed from: l */
    public final void m3979l() {
        View view = this.f9001g;
        if (view != null) {
            attachView(view);
        }
    }

    /* renamed from: m */
    public final void m3980m() {
        View view = this.f9001g;
        if (view != null) {
            detachView(view);
        }
    }

    /* renamed from: n */
    public final int m3981n(int i2) {
        int size = this.f8999e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (this.f8999e.get(i4).intValue() > i2) {
                size = i4 - 1;
            } else {
                if (this.f8999e.get(i4).intValue() >= i2) {
                    return i4;
                }
                i3 = i4 + 1;
            }
        }
        return -1;
    }

    /* renamed from: o */
    public final int m3982o(int i2) {
        int size = this.f8999e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (this.f8999e.get(i4).intValue() <= i2) {
                if (i4 < this.f8999e.size() - 1) {
                    int i5 = i4 + 1;
                    if (this.f8999e.get(i5).intValue() <= i2) {
                        i3 = i5;
                    }
                }
                return i4;
            }
            size = i4 - 1;
        }
        return -1;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAdapterChanged(RecyclerView.Adapter adapter, RecyclerView.Adapter adapter2) {
        super.onAdapterChanged(adapter, adapter2);
        m3985r(adapter2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAttachedToWindow(RecyclerView recyclerView) {
        super.onAttachedToWindow(recyclerView);
        m3985r(recyclerView.getAdapter());
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public View onFocusSearchFailed(View view, int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3980m();
        View onFocusSearchFailed = super.onFocusSearchFailed(view, i2, recycler, state);
        m3979l();
        return onFocusSearchFailed;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3980m();
        super.onLayoutChildren(recycler, state);
        m3979l();
        if (state.isPreLayout()) {
            return;
        }
        m3986s(recycler, true);
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof SavedState) {
            SavedState savedState = (SavedState) parcelable;
            this.f9003i = savedState.f9007e;
            this.f9004j = savedState.f9008f;
            parcelable = savedState.f9006c;
        }
        super.onRestoreInstanceState(parcelable);
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState();
        savedState.f9006c = super.onSaveInstanceState();
        savedState.f9007e = this.f9003i;
        savedState.f9008f = this.f9004j;
        return savedState;
    }

    /* renamed from: p */
    public final void m3983p(View view) {
        measureChildWithMargins(view, 0, 0);
        if (getOrientation() == 1) {
            view.layout(getPaddingLeft(), 0, getWidth() - getPaddingRight(), view.getMeasuredHeight());
        } else {
            view.layout(0, getPaddingTop(), view.getMeasuredWidth(), getHeight() - getPaddingBottom());
        }
    }

    /* renamed from: q */
    public final void m3984q(@Nullable RecyclerView.Recycler recycler) {
        View view = this.f9001g;
        this.f9001g = null;
        this.f9002h = -1;
        view.setTranslationX(0.0f);
        view.setTranslationY(0.0f);
        OnHoverAttachListener onHoverAttachListener = this.f8998c.f8900B;
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
    public final void m3985r(RecyclerView.Adapter adapter) {
        BindingAdapter bindingAdapter = this.f8998c;
        if (bindingAdapter != null) {
            bindingAdapter.unregisterAdapterDataObserver(this.f9000f);
        }
        if (!(adapter instanceof BindingAdapter)) {
            this.f8998c = null;
            this.f8999e.clear();
        } else {
            BindingAdapter bindingAdapter2 = (BindingAdapter) adapter;
            this.f8998c = bindingAdapter2;
            bindingAdapter2.registerAdapterDataObserver(this.f9000f);
            this.f9000f.onChanged();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:103:0x0077, code lost:
    
        if ((r8.getTranslationX() + r8.getLeft()) <= (getWidth() + 0.0f)) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x0086, code lost:
    
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
    
        r2 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x011f, code lost:
    
        if (r2 == false) goto L114;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00f2, code lost:
    
        if ((r8.getTranslationY() + r8.getTop()) < 0.0f) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x010d, code lost:
    
        if ((r8.getRight() - r8.getTranslationX()) > (getWidth() + 0.0f)) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x011c, code lost:
    
        if ((r8.getTranslationX() + r8.getLeft()) < 0.0f) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x005c, code lost:
    
        if ((r8.getBottom() - r8.getTranslationY()) >= 0.0f) goto L18;
     */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0090 A[LOOP:0: B:5:0x0010->B:19:0x0090, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x008b A[SYNTHETIC] */
    /* renamed from: s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3986s(androidx.recyclerview.widget.RecyclerView.Recycler r13, boolean r14) {
        /*
            Method dump skipped, instructions count: 529
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.drake.brv.layoutmanager.HoverStaggeredGridLayoutManager.m3986s(androidx.recyclerview.widget.RecyclerView$Recycler, boolean):void");
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3980m();
        int scrollHorizontallyBy = super.scrollHorizontallyBy(i2, recycler, state);
        m3979l();
        if (scrollHorizontallyBy != 0) {
            m3986s(recycler, false);
        }
        return scrollHorizontallyBy;
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void scrollToPosition(int i2) {
        scrollToPositionWithOffset(i2, Integer.MIN_VALUE);
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager
    public void scrollToPositionWithOffset(int i2, int i3) {
        this.f9003i = -1;
        this.f9004j = Integer.MIN_VALUE;
        int m3982o = m3982o(i2);
        if (m3982o == -1 || m3981n(i2) != -1) {
            super.scrollToPositionWithOffset(i2, i3);
            return;
        }
        int i4 = i2 - 1;
        if (m3981n(i4) != -1) {
            super.scrollToPositionWithOffset(i4, i3);
            return;
        }
        if (this.f9001g == null || m3982o != m3981n(this.f9002h)) {
            this.f9003i = i2;
            this.f9004j = i3;
            super.scrollToPositionWithOffset(i2, i3);
        } else {
            if (i3 == Integer.MIN_VALUE) {
                i3 = 0;
            }
            super.scrollToPositionWithOffset(i2, this.f9001g.getHeight() + i3);
        }
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3980m();
        int scrollVerticallyBy = super.scrollVerticallyBy(i2, recycler, state);
        m3979l();
        if (scrollVerticallyBy != 0) {
            m3986s(recycler, false);
        }
        return scrollVerticallyBy;
    }
}
