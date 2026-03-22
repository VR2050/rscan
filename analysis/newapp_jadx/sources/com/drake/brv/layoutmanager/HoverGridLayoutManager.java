package com.drake.brv.layoutmanager;

import android.content.Context;
import android.graphics.PointF;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.listener.OnHoverAttachListener;
import java.util.ArrayList;
import java.util.List;
import p005b.p177i.p178a.p182j.ViewTreeObserverOnGlobalLayoutListenerC1858a;

/* loaded from: classes.dex */
public class HoverGridLayoutManager extends GridLayoutManager {

    /* renamed from: c */
    public BindingAdapter f8973c;

    /* renamed from: e */
    public List<Integer> f8974e;

    /* renamed from: f */
    public RecyclerView.AdapterDataObserver f8975f;

    /* renamed from: g */
    public View f8976g;

    /* renamed from: h */
    public int f8977h;

    /* renamed from: i */
    public int f8978i;

    /* renamed from: j */
    public int f8979j;

    /* renamed from: k */
    public boolean f8980k;

    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new C3242a();

        /* renamed from: c */
        public Parcelable f8981c;

        /* renamed from: e */
        public int f8982e;

        /* renamed from: f */
        public int f8983f;

        /* renamed from: com.drake.brv.layoutmanager.HoverGridLayoutManager$SavedState$a */
        public class C3242a implements Parcelable.Creator<SavedState> {
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
            parcel.writeParcelable(this.f8981c, i2);
            parcel.writeInt(this.f8982e);
            parcel.writeInt(this.f8983f);
        }

        public SavedState(Parcel parcel) {
            this.f8981c = parcel.readParcelable(SavedState.class.getClassLoader());
            this.f8982e = parcel.readInt();
            this.f8983f = parcel.readInt();
        }
    }

    /* renamed from: com.drake.brv.layoutmanager.HoverGridLayoutManager$a */
    public class C3243a extends RecyclerView.AdapterDataObserver {
        public C3243a(ViewTreeObserverOnGlobalLayoutListenerC1858a viewTreeObserverOnGlobalLayoutListenerC1858a) {
        }

        /* renamed from: a */
        public final void m3968a(int i2) {
            int intValue = HoverGridLayoutManager.this.f8974e.remove(i2).intValue();
            int m3959k = HoverGridLayoutManager.m3959k(HoverGridLayoutManager.this, intValue);
            if (m3959k != -1) {
                HoverGridLayoutManager.this.f8974e.add(m3959k, Integer.valueOf(intValue));
            } else {
                HoverGridLayoutManager.this.f8974e.add(Integer.valueOf(intValue));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onChanged() {
            HoverGridLayoutManager.this.f8974e.clear();
            int itemCount = HoverGridLayoutManager.this.f8973c.getItemCount();
            for (int i2 = 0; i2 < itemCount; i2++) {
                if (HoverGridLayoutManager.this.f8973c.m3934k(i2)) {
                    HoverGridLayoutManager.this.f8974e.add(Integer.valueOf(i2));
                }
            }
            HoverGridLayoutManager hoverGridLayoutManager = HoverGridLayoutManager.this;
            if (hoverGridLayoutManager.f8976g == null || hoverGridLayoutManager.f8974e.contains(Integer.valueOf(hoverGridLayoutManager.f8977h))) {
                return;
            }
            HoverGridLayoutManager.this.m3965q(null);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeInserted(int i2, int i3) {
            int size = HoverGridLayoutManager.this.f8974e.size();
            if (size > 0) {
                for (int m3959k = HoverGridLayoutManager.m3959k(HoverGridLayoutManager.this, i2); m3959k != -1 && m3959k < size; m3959k++) {
                    List<Integer> list = HoverGridLayoutManager.this.f8974e;
                    list.set(m3959k, Integer.valueOf(list.get(m3959k).intValue() + i3));
                }
            }
            for (int i4 = i2; i4 < i2 + i3; i4++) {
                if (HoverGridLayoutManager.this.f8973c.m3934k(i4)) {
                    int m3959k2 = HoverGridLayoutManager.m3959k(HoverGridLayoutManager.this, i4);
                    if (m3959k2 != -1) {
                        HoverGridLayoutManager.this.f8974e.add(m3959k2, Integer.valueOf(i4));
                    } else {
                        HoverGridLayoutManager.this.f8974e.add(Integer.valueOf(i4));
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeMoved(int i2, int i3, int i4) {
            int size = HoverGridLayoutManager.this.f8974e.size();
            if (size > 0) {
                if (i2 < i3) {
                    for (int m3959k = HoverGridLayoutManager.m3959k(HoverGridLayoutManager.this, i2); m3959k != -1 && m3959k < size; m3959k++) {
                        int intValue = HoverGridLayoutManager.this.f8974e.get(m3959k).intValue();
                        if (intValue >= i2 && intValue < i2 + i4) {
                            HoverGridLayoutManager.this.f8974e.set(m3959k, Integer.valueOf(intValue - (i3 - i2)));
                            m3968a(m3959k);
                        } else {
                            if (intValue < i2 + i4 || intValue > i3) {
                                return;
                            }
                            HoverGridLayoutManager.this.f8974e.set(m3959k, Integer.valueOf(intValue - i4));
                            m3968a(m3959k);
                        }
                    }
                    return;
                }
                for (int m3959k2 = HoverGridLayoutManager.m3959k(HoverGridLayoutManager.this, i3); m3959k2 != -1 && m3959k2 < size; m3959k2++) {
                    int intValue2 = HoverGridLayoutManager.this.f8974e.get(m3959k2).intValue();
                    if (intValue2 >= i2 && intValue2 < i2 + i4) {
                        HoverGridLayoutManager.this.f8974e.set(m3959k2, Integer.valueOf((i3 - i2) + intValue2));
                        m3968a(m3959k2);
                    } else {
                        if (intValue2 < i3 || intValue2 > i2) {
                            return;
                        }
                        HoverGridLayoutManager.this.f8974e.set(m3959k2, Integer.valueOf(intValue2 + i4));
                        m3968a(m3959k2);
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public void onItemRangeRemoved(int i2, int i3) {
            int size = HoverGridLayoutManager.this.f8974e.size();
            if (size > 0) {
                int i4 = i2 + i3;
                for (int i5 = i4 - 1; i5 >= i2; i5--) {
                    int m3962n = HoverGridLayoutManager.this.m3962n(i5);
                    if (m3962n != -1) {
                        HoverGridLayoutManager.this.f8974e.remove(m3962n);
                        size--;
                    }
                }
                HoverGridLayoutManager hoverGridLayoutManager = HoverGridLayoutManager.this;
                if (hoverGridLayoutManager.f8976g != null && !hoverGridLayoutManager.f8974e.contains(Integer.valueOf(hoverGridLayoutManager.f8977h))) {
                    HoverGridLayoutManager.this.m3965q(null);
                }
                for (int m3959k = HoverGridLayoutManager.m3959k(HoverGridLayoutManager.this, i4); m3959k != -1 && m3959k < size; m3959k++) {
                    List<Integer> list = HoverGridLayoutManager.this.f8974e;
                    list.set(m3959k, Integer.valueOf(list.get(m3959k).intValue() - i3));
                }
            }
        }
    }

    public HoverGridLayoutManager(Context context, int i2, int i3, boolean z) {
        super(context, i2, i3, z);
        this.f8974e = new ArrayList(0);
        this.f8975f = new C3243a(null);
        this.f8977h = -1;
        this.f8978i = -1;
        this.f8979j = 0;
        this.f8980k = true;
    }

    /* renamed from: k */
    public static int m3959k(HoverGridLayoutManager hoverGridLayoutManager, int i2) {
        int size = hoverGridLayoutManager.f8974e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (i4 > 0) {
                int i5 = i4 - 1;
                if (hoverGridLayoutManager.f8974e.get(i5).intValue() >= i2) {
                    size = i5;
                }
            }
            if (hoverGridLayoutManager.f8974e.get(i4).intValue() >= i2) {
                return i4;
            }
            i3 = i4 + 1;
        }
        return -1;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollHorizontally() {
        return super.canScrollHorizontally() && this.f8980k;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollVertically() {
        return super.canScrollVertically() && this.f8980k;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollExtent(RecyclerView.State state) {
        m3961m();
        int computeHorizontalScrollExtent = super.computeHorizontalScrollExtent(state);
        m3960l();
        return computeHorizontalScrollExtent;
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollOffset(RecyclerView.State state) {
        m3961m();
        int computeHorizontalScrollOffset = super.computeHorizontalScrollOffset(state);
        m3960l();
        return computeHorizontalScrollOffset;
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollRange(RecyclerView.State state) {
        m3961m();
        int computeHorizontalScrollRange = super.computeHorizontalScrollRange(state);
        m3960l();
        return computeHorizontalScrollRange;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.SmoothScroller.ScrollVectorProvider
    public PointF computeScrollVectorForPosition(int i2) {
        m3961m();
        PointF computeScrollVectorForPosition = super.computeScrollVectorForPosition(i2);
        m3960l();
        return computeScrollVectorForPosition;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollExtent(RecyclerView.State state) {
        m3961m();
        int computeVerticalScrollExtent = super.computeVerticalScrollExtent(state);
        m3960l();
        return computeVerticalScrollExtent;
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollOffset(RecyclerView.State state) {
        m3961m();
        int computeVerticalScrollOffset = super.computeVerticalScrollOffset(state);
        m3960l();
        return computeVerticalScrollOffset;
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollRange(RecyclerView.State state) {
        m3961m();
        int computeVerticalScrollRange = super.computeVerticalScrollRange(state);
        m3960l();
        return computeVerticalScrollRange;
    }

    /* renamed from: l */
    public final void m3960l() {
        View view = this.f8976g;
        if (view != null) {
            attachView(view);
        }
    }

    /* renamed from: m */
    public final void m3961m() {
        View view = this.f8976g;
        if (view != null) {
            detachView(view);
        }
    }

    /* renamed from: n */
    public final int m3962n(int i2) {
        int size = this.f8974e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (this.f8974e.get(i4).intValue() > i2) {
                size = i4 - 1;
            } else {
                if (this.f8974e.get(i4).intValue() >= i2) {
                    return i4;
                }
                i3 = i4 + 1;
            }
        }
        return -1;
    }

    /* renamed from: o */
    public final int m3963o(int i2) {
        int size = this.f8974e.size() - 1;
        int i3 = 0;
        while (i3 <= size) {
            int i4 = (i3 + size) / 2;
            if (this.f8974e.get(i4).intValue() <= i2) {
                if (i4 < this.f8974e.size() - 1) {
                    int i5 = i4 + 1;
                    if (this.f8974e.get(i5).intValue() <= i2) {
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
        m3966r(adapter2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAttachedToWindow(RecyclerView recyclerView) {
        super.onAttachedToWindow(recyclerView);
        m3966r(recyclerView.getAdapter());
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public View onFocusSearchFailed(View view, int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3961m();
        View onFocusSearchFailed = super.onFocusSearchFailed(view, i2, recycler, state);
        m3960l();
        return onFocusSearchFailed;
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3961m();
        super.onLayoutChildren(recycler, state);
        m3960l();
        if (state.isPreLayout()) {
            return;
        }
        m3967s(recycler, true);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof SavedState) {
            SavedState savedState = (SavedState) parcelable;
            this.f8978i = savedState.f8982e;
            this.f8979j = savedState.f8983f;
            parcelable = savedState.f8981c;
        }
        super.onRestoreInstanceState(parcelable);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState();
        savedState.f8981c = super.onSaveInstanceState();
        savedState.f8982e = this.f8978i;
        savedState.f8983f = this.f8979j;
        return savedState;
    }

    /* renamed from: p */
    public final void m3964p(View view) {
        measureChildWithMargins(view, 0, 0);
        if (getOrientation() == 1) {
            view.layout(getPaddingLeft(), 0, getWidth() - getPaddingRight(), view.getMeasuredHeight());
        } else {
            view.layout(0, getPaddingTop(), view.getMeasuredWidth(), getHeight() - getPaddingBottom());
        }
    }

    /* renamed from: q */
    public final void m3965q(@Nullable RecyclerView.Recycler recycler) {
        View view = this.f8976g;
        this.f8976g = null;
        this.f8977h = -1;
        view.setTranslationX(0.0f);
        view.setTranslationY(0.0f);
        OnHoverAttachListener onHoverAttachListener = this.f8973c.f8900B;
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
    public final void m3966r(RecyclerView.Adapter adapter) {
        BindingAdapter bindingAdapter = this.f8973c;
        if (bindingAdapter != null) {
            bindingAdapter.unregisterAdapterDataObserver(this.f8975f);
        }
        if (!(adapter instanceof BindingAdapter)) {
            this.f8973c = null;
            this.f8974e.clear();
        } else {
            BindingAdapter bindingAdapter2 = (BindingAdapter) adapter;
            this.f8973c = bindingAdapter2;
            bindingAdapter2.registerAdapterDataObserver(this.f8975f);
            this.f8975f.onChanged();
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
    public final void m3967s(androidx.recyclerview.widget.RecyclerView.Recycler r13, boolean r14) {
        /*
            Method dump skipped, instructions count: 529
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.drake.brv.layoutmanager.HoverGridLayoutManager.m3967s(androidx.recyclerview.widget.RecyclerView$Recycler, boolean):void");
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3961m();
        int scrollHorizontallyBy = super.scrollHorizontallyBy(i2, recycler, state);
        m3960l();
        if (scrollHorizontallyBy != 0) {
            m3967s(recycler, false);
        }
        return scrollHorizontallyBy;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void scrollToPosition(int i2) {
        scrollToPositionWithOffset(i2, Integer.MIN_VALUE);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public void scrollToPositionWithOffset(int i2, int i3) {
        this.f8978i = -1;
        this.f8979j = Integer.MIN_VALUE;
        int m3963o = m3963o(i2);
        if (m3963o == -1 || m3962n(i2) != -1) {
            super.scrollToPositionWithOffset(i2, i3);
            return;
        }
        int i4 = i2 - 1;
        if (m3962n(i4) != -1) {
            super.scrollToPositionWithOffset(i4, i3);
            return;
        }
        if (this.f8976g == null || m3963o != m3962n(this.f8977h)) {
            this.f8978i = i2;
            this.f8979j = i3;
            super.scrollToPositionWithOffset(i2, i3);
        } else {
            if (i3 == Integer.MIN_VALUE) {
                i3 = 0;
            }
            super.scrollToPositionWithOffset(i2, this.f8976g.getHeight() + i3);
        }
    }

    @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        m3961m();
        int scrollVerticallyBy = super.scrollVerticallyBy(i2, recycler, state);
        m3960l();
        if (scrollVerticallyBy != 0) {
            m3967s(recycler, false);
        }
        return scrollVerticallyBy;
    }

    public HoverGridLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        super(context, attributeSet, i2, i3);
        this.f8974e = new ArrayList(0);
        this.f8975f = new C3243a(null);
        this.f8977h = -1;
        this.f8978i = -1;
        this.f8979j = 0;
        this.f8980k = true;
    }
}
