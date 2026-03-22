package com.google.android.flexbox;

import android.content.Context;
import android.graphics.PointF;
import android.graphics.Rect;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.LinearSmoothScroller;
import androidx.recyclerview.widget.OrientationHelper;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p254b.C2411b;
import p005b.p199l.p200a.p254b.C2412c;
import p005b.p199l.p200a.p254b.InterfaceC2410a;

/* loaded from: classes.dex */
public class FlexboxLayoutManager extends RecyclerView.LayoutManager implements InterfaceC2410a, RecyclerView.SmoothScroller.ScrollVectorProvider {

    /* renamed from: c */
    public static final Rect f9786c = new Rect();

    /* renamed from: e */
    public int f9789e;

    /* renamed from: f */
    public int f9790f;

    /* renamed from: g */
    public int f9791g;

    /* renamed from: i */
    public boolean f9793i;

    /* renamed from: j */
    public boolean f9794j;

    /* renamed from: m */
    public RecyclerView.Recycler f9797m;

    /* renamed from: n */
    public RecyclerView.State f9798n;

    /* renamed from: o */
    public C3335c f9799o;

    /* renamed from: q */
    public OrientationHelper f9801q;

    /* renamed from: r */
    public OrientationHelper f9802r;

    /* renamed from: s */
    public SavedState f9803s;

    /* renamed from: y */
    public final Context f9809y;

    /* renamed from: z */
    public View f9810z;

    /* renamed from: h */
    public int f9792h = -1;

    /* renamed from: k */
    public List<C2411b> f9795k = new ArrayList();

    /* renamed from: l */
    public final C2412c f9796l = new C2412c(this);

    /* renamed from: p */
    public C3334b f9800p = new C3334b(null);

    /* renamed from: t */
    public int f9804t = -1;

    /* renamed from: u */
    public int f9805u = Integer.MIN_VALUE;

    /* renamed from: v */
    public int f9806v = Integer.MIN_VALUE;

    /* renamed from: w */
    public int f9807w = Integer.MIN_VALUE;

    /* renamed from: x */
    public SparseArray<View> f9808x = new SparseArray<>();

    /* renamed from: A */
    public int f9787A = -1;

    /* renamed from: B */
    public C2412c.b f9788B = new C2412c.b();

    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new C3332a();

        /* renamed from: c */
        public int f9820c;

        /* renamed from: e */
        public int f9821e;

        /* renamed from: com.google.android.flexbox.FlexboxLayoutManager$SavedState$a */
        public static class C3332a implements Parcelable.Creator<SavedState> {
            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel parcel) {
                return new SavedState(parcel, (C3333a) null);
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

        public String toString() {
            StringBuilder m586H = C1499a.m586H("SavedState{mAnchorPosition=");
            m586H.append(this.f9820c);
            m586H.append(", mAnchorOffset=");
            return C1499a.m579A(m586H, this.f9821e, '}');
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeInt(this.f9820c);
            parcel.writeInt(this.f9821e);
        }

        public SavedState(Parcel parcel, C3333a c3333a) {
            this.f9820c = parcel.readInt();
            this.f9821e = parcel.readInt();
        }

        public SavedState(SavedState savedState, C3333a c3333a) {
            this.f9820c = savedState.f9820c;
            this.f9821e = savedState.f9821e;
        }
    }

    /* renamed from: com.google.android.flexbox.FlexboxLayoutManager$b */
    public class C3334b {

        /* renamed from: a */
        public int f9822a;

        /* renamed from: b */
        public int f9823b;

        /* renamed from: c */
        public int f9824c;

        /* renamed from: d */
        public int f9825d = 0;

        /* renamed from: e */
        public boolean f9826e;

        /* renamed from: f */
        public boolean f9827f;

        /* renamed from: g */
        public boolean f9828g;

        public C3334b(C3333a c3333a) {
        }

        /* renamed from: a */
        public static void m4178a(C3334b c3334b) {
            if (!FlexboxLayoutManager.this.mo2718i()) {
                FlexboxLayoutManager flexboxLayoutManager = FlexboxLayoutManager.this;
                if (flexboxLayoutManager.f9793i) {
                    c3334b.f9824c = c3334b.f9826e ? flexboxLayoutManager.f9801q.getEndAfterPadding() : flexboxLayoutManager.getWidth() - FlexboxLayoutManager.this.f9801q.getStartAfterPadding();
                    return;
                }
            }
            c3334b.f9824c = c3334b.f9826e ? FlexboxLayoutManager.this.f9801q.getEndAfterPadding() : FlexboxLayoutManager.this.f9801q.getStartAfterPadding();
        }

        /* renamed from: b */
        public static void m4179b(C3334b c3334b) {
            c3334b.f9822a = -1;
            c3334b.f9823b = -1;
            c3334b.f9824c = Integer.MIN_VALUE;
            c3334b.f9827f = false;
            c3334b.f9828g = false;
            if (FlexboxLayoutManager.this.mo2718i()) {
                FlexboxLayoutManager flexboxLayoutManager = FlexboxLayoutManager.this;
                int i2 = flexboxLayoutManager.f9790f;
                if (i2 == 0) {
                    c3334b.f9826e = flexboxLayoutManager.f9789e == 1;
                    return;
                } else {
                    c3334b.f9826e = i2 == 2;
                    return;
                }
            }
            FlexboxLayoutManager flexboxLayoutManager2 = FlexboxLayoutManager.this;
            int i3 = flexboxLayoutManager2.f9790f;
            if (i3 == 0) {
                c3334b.f9826e = flexboxLayoutManager2.f9789e == 3;
            } else {
                c3334b.f9826e = i3 == 2;
            }
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("AnchorInfo{mPosition=");
            m586H.append(this.f9822a);
            m586H.append(", mFlexLinePosition=");
            m586H.append(this.f9823b);
            m586H.append(", mCoordinate=");
            m586H.append(this.f9824c);
            m586H.append(", mPerpendicularCoordinate=");
            m586H.append(this.f9825d);
            m586H.append(", mLayoutFromEnd=");
            m586H.append(this.f9826e);
            m586H.append(", mValid=");
            m586H.append(this.f9827f);
            m586H.append(", mAssignedFromSavedState=");
            m586H.append(this.f9828g);
            m586H.append('}');
            return m586H.toString();
        }
    }

    /* renamed from: com.google.android.flexbox.FlexboxLayoutManager$c */
    public static class C3335c {

        /* renamed from: a */
        public int f9830a;

        /* renamed from: b */
        public boolean f9831b;

        /* renamed from: c */
        public int f9832c;

        /* renamed from: d */
        public int f9833d;

        /* renamed from: e */
        public int f9834e;

        /* renamed from: f */
        public int f9835f;

        /* renamed from: g */
        public int f9836g;

        /* renamed from: h */
        public int f9837h = 1;

        /* renamed from: i */
        public int f9838i = 1;

        /* renamed from: j */
        public boolean f9839j;

        public C3335c(C3333a c3333a) {
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("LayoutState{mAvailable=");
            m586H.append(this.f9830a);
            m586H.append(", mFlexLinePosition=");
            m586H.append(this.f9832c);
            m586H.append(", mPosition=");
            m586H.append(this.f9833d);
            m586H.append(", mOffset=");
            m586H.append(this.f9834e);
            m586H.append(", mScrollingOffset=");
            m586H.append(this.f9835f);
            m586H.append(", mLastScrollDelta=");
            m586H.append(this.f9836g);
            m586H.append(", mItemDirection=");
            m586H.append(this.f9837h);
            m586H.append(", mLayoutDirection=");
            return C1499a.m579A(m586H, this.f9838i, '}');
        }
    }

    public FlexboxLayoutManager(Context context) {
        m4175x(0);
        m4176y(1);
        if (this.f9791g != 4) {
            removeAllViews();
            m4162k();
            this.f9791g = 4;
            requestLayout();
        }
        setAutoMeasureEnabled(true);
        this.f9809y = context;
    }

    public static boolean isMeasurementUpToDate(int i2, int i3, int i4) {
        int mode = View.MeasureSpec.getMode(i3);
        int size = View.MeasureSpec.getSize(i3);
        if (i4 > 0 && i2 != i4) {
            return false;
        }
        if (mode == Integer.MIN_VALUE) {
            return size >= i2;
        }
        if (mode != 0) {
            return mode == 1073741824 && size == i2;
        }
        return true;
    }

    private boolean shouldMeasureChild(View view, int i2, int i3, RecyclerView.LayoutParams layoutParams) {
        return (!view.isLayoutRequested() && isMeasurementCacheEnabled() && isMeasurementUpToDate(view.getWidth(), i2, ((ViewGroup.MarginLayoutParams) layoutParams).width) && isMeasurementUpToDate(view.getHeight(), i3, ((ViewGroup.MarginLayoutParams) layoutParams).height)) ? false : true;
    }

    /* renamed from: A */
    public final void m4160A(C3334b c3334b, boolean z, boolean z2) {
        int i2;
        if (z2) {
            m4174w();
        } else {
            this.f9799o.f9831b = false;
        }
        if (mo2718i() || !this.f9793i) {
            this.f9799o.f9830a = this.f9801q.getEndAfterPadding() - c3334b.f9824c;
        } else {
            this.f9799o.f9830a = c3334b.f9824c - getPaddingRight();
        }
        C3335c c3335c = this.f9799o;
        c3335c.f9833d = c3334b.f9822a;
        c3335c.f9837h = 1;
        c3335c.f9838i = 1;
        c3335c.f9834e = c3334b.f9824c;
        c3335c.f9835f = Integer.MIN_VALUE;
        c3335c.f9832c = c3334b.f9823b;
        if (!z || this.f9795k.size() <= 1 || (i2 = c3334b.f9823b) < 0 || i2 >= this.f9795k.size() - 1) {
            return;
        }
        C2411b c2411b = this.f9795k.get(c3334b.f9823b);
        C3335c c3335c2 = this.f9799o;
        c3335c2.f9832c++;
        c3335c2.f9833d += c2411b.f6425h;
    }

    /* renamed from: B */
    public final void m4161B(C3334b c3334b, boolean z, boolean z2) {
        if (z2) {
            m4174w();
        } else {
            this.f9799o.f9831b = false;
        }
        if (mo2718i() || !this.f9793i) {
            this.f9799o.f9830a = c3334b.f9824c - this.f9801q.getStartAfterPadding();
        } else {
            this.f9799o.f9830a = (this.f9810z.getWidth() - c3334b.f9824c) - this.f9801q.getStartAfterPadding();
        }
        C3335c c3335c = this.f9799o;
        c3335c.f9833d = c3334b.f9822a;
        c3335c.f9837h = 1;
        c3335c.f9838i = -1;
        c3335c.f9834e = c3334b.f9824c;
        c3335c.f9835f = Integer.MIN_VALUE;
        int i2 = c3334b.f9823b;
        c3335c.f9832c = i2;
        if (!z || i2 <= 0) {
            return;
        }
        int size = this.f9795k.size();
        int i3 = c3334b.f9823b;
        if (size > i3) {
            C2411b c2411b = this.f9795k.get(i3);
            r4.f9832c--;
            this.f9799o.f9833d -= c2411b.f6425h;
        }
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: a */
    public void mo2710a(View view, int i2, int i3, C2411b c2411b) {
        calculateItemDecorationsForChild(view, f9786c);
        if (mo2718i()) {
            int rightDecorationWidth = getRightDecorationWidth(view) + getLeftDecorationWidth(view);
            c2411b.f6422e += rightDecorationWidth;
            c2411b.f6423f += rightDecorationWidth;
            return;
        }
        int bottomDecorationHeight = getBottomDecorationHeight(view) + getTopDecorationHeight(view);
        c2411b.f6422e += bottomDecorationHeight;
        c2411b.f6423f += bottomDecorationHeight;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: b */
    public void mo2711b(C2411b c2411b) {
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: c */
    public View mo2712c(int i2) {
        return mo2715f(i2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollHorizontally() {
        if (this.f9790f == 0) {
            return mo2718i();
        }
        if (mo2718i()) {
            int width = getWidth();
            View view = this.f9810z;
            if (width <= (view != null ? view.getWidth() : 0)) {
                return false;
            }
        }
        return true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollVertically() {
        if (this.f9790f == 0) {
            return !mo2718i();
        }
        if (mo2718i()) {
            return true;
        }
        int height = getHeight();
        View view = this.f9810z;
        return height > (view != null ? view.getHeight() : 0);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean checkLayoutParams(RecyclerView.LayoutParams layoutParams) {
        return layoutParams instanceof LayoutParams;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollExtent(RecyclerView.State state) {
        return computeScrollExtent(state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollOffset(RecyclerView.State state) {
        return computeScrollOffset(state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollRange(RecyclerView.State state) {
        return computeScrollRange(state);
    }

    public final int computeScrollExtent(RecyclerView.State state) {
        if (getChildCount() == 0) {
            return 0;
        }
        int itemCount = state.getItemCount();
        m4163l();
        View m4165n = m4165n(itemCount);
        View m4167p = m4167p(itemCount);
        if (state.getItemCount() == 0 || m4165n == null || m4167p == null) {
            return 0;
        }
        return Math.min(this.f9801q.getTotalSpace(), this.f9801q.getDecoratedEnd(m4167p) - this.f9801q.getDecoratedStart(m4165n));
    }

    public final int computeScrollOffset(RecyclerView.State state) {
        if (getChildCount() == 0) {
            return 0;
        }
        int itemCount = state.getItemCount();
        View m4165n = m4165n(itemCount);
        View m4167p = m4167p(itemCount);
        if (state.getItemCount() != 0 && m4165n != null && m4167p != null) {
            int position = getPosition(m4165n);
            int position2 = getPosition(m4167p);
            int abs = Math.abs(this.f9801q.getDecoratedEnd(m4167p) - this.f9801q.getDecoratedStart(m4165n));
            int i2 = this.f9796l.f6438c[position];
            if (i2 != 0 && i2 != -1) {
                return Math.round((i2 * (abs / ((r4[position2] - i2) + 1))) + (this.f9801q.getStartAfterPadding() - this.f9801q.getDecoratedStart(m4165n)));
            }
        }
        return 0;
    }

    public final int computeScrollRange(RecyclerView.State state) {
        if (getChildCount() == 0) {
            return 0;
        }
        int itemCount = state.getItemCount();
        View m4165n = m4165n(itemCount);
        View m4167p = m4167p(itemCount);
        if (state.getItemCount() == 0 || m4165n == null || m4167p == null) {
            return 0;
        }
        return (int) ((Math.abs(this.f9801q.getDecoratedEnd(m4167p) - this.f9801q.getDecoratedStart(m4165n)) / ((findLastVisibleItemPosition() - (m4169r(0, getChildCount(), false) == null ? -1 : getPosition(r1))) + 1)) * state.getItemCount());
    }

    @Override // androidx.recyclerview.widget.RecyclerView.SmoothScroller.ScrollVectorProvider
    public PointF computeScrollVectorForPosition(int i2) {
        if (getChildCount() == 0) {
            return null;
        }
        int i3 = i2 < getPosition(getChildAt(0)) ? -1 : 1;
        return mo2718i() ? new PointF(0.0f, i3) : new PointF(i3, 0.0f);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollExtent(RecyclerView.State state) {
        return computeScrollExtent(state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollOffset(RecyclerView.State state) {
        return computeScrollOffset(state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollRange(RecyclerView.State state) {
        return computeScrollRange(state);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: d */
    public int mo2713d(int i2, int i3, int i4) {
        return RecyclerView.LayoutManager.getChildMeasureSpec(getWidth(), getWidthMode(), i3, i4, canScrollHorizontally());
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: e */
    public void mo2714e(int i2, View view) {
        this.f9808x.put(i2, view);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: f */
    public View mo2715f(int i2) {
        View view = this.f9808x.get(i2);
        return view != null ? view : this.f9797m.getViewForPosition(i2);
    }

    public int findLastVisibleItemPosition() {
        View m4169r = m4169r(getChildCount() - 1, -1, false);
        if (m4169r == null) {
            return -1;
        }
        return getPosition(m4169r);
    }

    public final int fixLayoutEndGap(int i2, RecyclerView.Recycler recycler, RecyclerView.State state, boolean z) {
        int i3;
        int endAfterPadding;
        if (!mo2718i() && this.f9793i) {
            int startAfterPadding = i2 - this.f9801q.getStartAfterPadding();
            if (startAfterPadding <= 0) {
                return 0;
            }
            i3 = m4171t(startAfterPadding, recycler, state);
        } else {
            int endAfterPadding2 = this.f9801q.getEndAfterPadding() - i2;
            if (endAfterPadding2 <= 0) {
                return 0;
            }
            i3 = -m4171t(-endAfterPadding2, recycler, state);
        }
        int i4 = i2 + i3;
        if (!z || (endAfterPadding = this.f9801q.getEndAfterPadding() - i4) <= 0) {
            return i3;
        }
        this.f9801q.offsetChildren(endAfterPadding);
        return endAfterPadding + i3;
    }

    public final int fixLayoutStartGap(int i2, RecyclerView.Recycler recycler, RecyclerView.State state, boolean z) {
        int i3;
        int startAfterPadding;
        if (mo2718i() || !this.f9793i) {
            int startAfterPadding2 = i2 - this.f9801q.getStartAfterPadding();
            if (startAfterPadding2 <= 0) {
                return 0;
            }
            i3 = -m4171t(startAfterPadding2, recycler, state);
        } else {
            int endAfterPadding = this.f9801q.getEndAfterPadding() - i2;
            if (endAfterPadding <= 0) {
                return 0;
            }
            i3 = m4171t(-endAfterPadding, recycler, state);
        }
        int i4 = i2 + i3;
        if (!z || (startAfterPadding = i4 - this.f9801q.getStartAfterPadding()) <= 0) {
            return i3;
        }
        this.f9801q.offsetChildren(-startAfterPadding);
        return i3 - startAfterPadding;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: g */
    public int mo2716g(View view, int i2, int i3) {
        int topDecorationHeight;
        int bottomDecorationHeight;
        if (mo2718i()) {
            topDecorationHeight = getLeftDecorationWidth(view);
            bottomDecorationHeight = getRightDecorationWidth(view);
        } else {
            topDecorationHeight = getTopDecorationHeight(view);
            bottomDecorationHeight = getBottomDecorationHeight(view);
        }
        return bottomDecorationHeight + topDecorationHeight;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public RecyclerView.LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams(-2, -2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public RecyclerView.LayoutParams generateLayoutParams(Context context, AttributeSet attributeSet) {
        return new LayoutParams(context, attributeSet);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getAlignContent() {
        return 5;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getAlignItems() {
        return this.f9791g;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getFlexDirection() {
        return this.f9789e;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getFlexItemCount() {
        return this.f9798n.getItemCount();
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public List<C2411b> getFlexLinesInternal() {
        return this.f9795k;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getFlexWrap() {
        return this.f9790f;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getLargestMainSize() {
        if (this.f9795k.size() == 0) {
            return 0;
        }
        int i2 = Integer.MIN_VALUE;
        int size = this.f9795k.size();
        for (int i3 = 0; i3 < size; i3++) {
            i2 = Math.max(i2, this.f9795k.get(i3).f6422e);
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getMaxLine() {
        return this.f9792h;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getSumOfCrossSize() {
        int size = this.f9795k.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            i2 += this.f9795k.get(i3).f6424g;
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: h */
    public int mo2717h(int i2, int i3, int i4) {
        return RecyclerView.LayoutManager.getChildMeasureSpec(getHeight(), getHeightMode(), i3, i4, canScrollVertically());
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: i */
    public boolean mo2718i() {
        int i2 = this.f9789e;
        return i2 == 0 || i2 == 1;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: j */
    public int mo2719j(View view) {
        int leftDecorationWidth;
        int rightDecorationWidth;
        if (mo2718i()) {
            leftDecorationWidth = getTopDecorationHeight(view);
            rightDecorationWidth = getBottomDecorationHeight(view);
        } else {
            leftDecorationWidth = getLeftDecorationWidth(view);
            rightDecorationWidth = getRightDecorationWidth(view);
        }
        return rightDecorationWidth + leftDecorationWidth;
    }

    /* renamed from: k */
    public final void m4162k() {
        this.f9795k.clear();
        C3334b.m4179b(this.f9800p);
        this.f9800p.f9825d = 0;
    }

    /* renamed from: l */
    public final void m4163l() {
        if (this.f9801q != null) {
            return;
        }
        if (mo2718i()) {
            if (this.f9790f == 0) {
                this.f9801q = OrientationHelper.createHorizontalHelper(this);
                this.f9802r = OrientationHelper.createVerticalHelper(this);
                return;
            } else {
                this.f9801q = OrientationHelper.createVerticalHelper(this);
                this.f9802r = OrientationHelper.createHorizontalHelper(this);
                return;
            }
        }
        if (this.f9790f == 0) {
            this.f9801q = OrientationHelper.createVerticalHelper(this);
            this.f9802r = OrientationHelper.createHorizontalHelper(this);
        } else {
            this.f9801q = OrientationHelper.createHorizontalHelper(this);
            this.f9802r = OrientationHelper.createVerticalHelper(this);
        }
    }

    /* renamed from: m */
    public final int m4164m(RecyclerView.Recycler recycler, RecyclerView.State state, C3335c c3335c) {
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        int i16;
        int i17 = c3335c.f9835f;
        if (i17 != Integer.MIN_VALUE) {
            int i18 = c3335c.f9830a;
            if (i18 < 0) {
                c3335c.f9835f = i17 + i18;
            }
            m4173v(recycler, c3335c);
        }
        int i19 = c3335c.f9830a;
        boolean mo2718i = mo2718i();
        int i20 = i19;
        int i21 = 0;
        while (true) {
            if (i20 <= 0 && !this.f9799o.f9831b) {
                break;
            }
            List<C2411b> list = this.f9795k;
            int i22 = c3335c.f9833d;
            if (!(i22 >= 0 && i22 < state.getItemCount() && (i16 = c3335c.f9832c) >= 0 && i16 < list.size())) {
                break;
            }
            C2411b c2411b = this.f9795k.get(c3335c.f9832c);
            c3335c.f9833d = c2411b.f6432o;
            if (mo2718i()) {
                int paddingLeft = getPaddingLeft();
                int paddingRight = getPaddingRight();
                int width = getWidth();
                int i23 = c3335c.f9834e;
                if (c3335c.f9838i == -1) {
                    i23 -= c2411b.f6424g;
                }
                int i24 = c3335c.f9833d;
                float f2 = width - paddingRight;
                float f3 = this.f9800p.f9825d;
                float f4 = paddingLeft - f3;
                float f5 = f2 - f3;
                float max = Math.max(0.0f, 0.0f);
                int i25 = c2411b.f6425h;
                int i26 = i24;
                int i27 = 0;
                while (i26 < i24 + i25) {
                    View mo2715f = mo2715f(i26);
                    if (mo2715f == null) {
                        i13 = i19;
                        i12 = i24;
                        i14 = i26;
                        i15 = i25;
                    } else {
                        i12 = i24;
                        int i28 = i25;
                        if (c3335c.f9838i == 1) {
                            calculateItemDecorationsForChild(mo2715f, f9786c);
                            addView(mo2715f);
                        } else {
                            calculateItemDecorationsForChild(mo2715f, f9786c);
                            addView(mo2715f, i27);
                            i27++;
                        }
                        int i29 = i27;
                        C2412c c2412c = this.f9796l;
                        i13 = i19;
                        long j2 = c2412c.f6439d[i26];
                        int i30 = (int) j2;
                        int m2736m = c2412c.m2736m(j2);
                        if (shouldMeasureChild(mo2715f, i30, m2736m, (LayoutParams) mo2715f.getLayoutParams())) {
                            mo2715f.measure(i30, m2736m);
                        }
                        float leftDecorationWidth = f4 + getLeftDecorationWidth(mo2715f) + ((ViewGroup.MarginLayoutParams) r4).leftMargin;
                        float rightDecorationWidth = f5 - (getRightDecorationWidth(mo2715f) + ((ViewGroup.MarginLayoutParams) r4).rightMargin);
                        int topDecorationHeight = getTopDecorationHeight(mo2715f) + i23;
                        if (this.f9793i) {
                            i14 = i26;
                            i15 = i28;
                            this.f9796l.m2744u(mo2715f, c2411b, Math.round(rightDecorationWidth) - mo2715f.getMeasuredWidth(), topDecorationHeight, Math.round(rightDecorationWidth), mo2715f.getMeasuredHeight() + topDecorationHeight);
                        } else {
                            i14 = i26;
                            i15 = i28;
                            this.f9796l.m2744u(mo2715f, c2411b, Math.round(leftDecorationWidth), topDecorationHeight, mo2715f.getMeasuredWidth() + Math.round(leftDecorationWidth), mo2715f.getMeasuredHeight() + topDecorationHeight);
                        }
                        f5 = rightDecorationWidth - ((getLeftDecorationWidth(mo2715f) + (mo2715f.getMeasuredWidth() + ((ViewGroup.MarginLayoutParams) r4).leftMargin)) + max);
                        f4 = getRightDecorationWidth(mo2715f) + mo2715f.getMeasuredWidth() + ((ViewGroup.MarginLayoutParams) r4).rightMargin + max + leftDecorationWidth;
                        i27 = i29;
                    }
                    i26 = i14 + 1;
                    i24 = i12;
                    i19 = i13;
                    i25 = i15;
                }
                i2 = i19;
                c3335c.f9832c += this.f9799o.f9838i;
                i6 = c2411b.f6424g;
                i4 = i20;
                i5 = i21;
            } else {
                i2 = i19;
                int paddingTop = getPaddingTop();
                int paddingBottom = getPaddingBottom();
                int height = getHeight();
                int i31 = c3335c.f9834e;
                if (c3335c.f9838i == -1) {
                    int i32 = c2411b.f6424g;
                    int i33 = i31 - i32;
                    i3 = i31 + i32;
                    i31 = i33;
                } else {
                    i3 = i31;
                }
                int i34 = c3335c.f9833d;
                float f6 = height - paddingBottom;
                float f7 = this.f9800p.f9825d;
                float f8 = paddingTop - f7;
                float f9 = f6 - f7;
                float max2 = Math.max(0.0f, 0.0f);
                int i35 = c2411b.f6425h;
                int i36 = i34;
                int i37 = 0;
                while (i36 < i34 + i35) {
                    View mo2715f2 = mo2715f(i36);
                    if (mo2715f2 == null) {
                        i7 = i20;
                        i8 = i21;
                        i9 = i36;
                        i10 = i35;
                        i11 = i34;
                    } else {
                        int i38 = i35;
                        C2412c c2412c2 = this.f9796l;
                        int i39 = i34;
                        i7 = i20;
                        i8 = i21;
                        long j3 = c2412c2.f6439d[i36];
                        int i40 = (int) j3;
                        int m2736m2 = c2412c2.m2736m(j3);
                        if (shouldMeasureChild(mo2715f2, i40, m2736m2, (LayoutParams) mo2715f2.getLayoutParams())) {
                            mo2715f2.measure(i40, m2736m2);
                        }
                        float topDecorationHeight2 = f8 + getTopDecorationHeight(mo2715f2) + ((ViewGroup.MarginLayoutParams) r8).topMargin;
                        float bottomDecorationHeight = f9 - (getBottomDecorationHeight(mo2715f2) + ((ViewGroup.MarginLayoutParams) r8).rightMargin);
                        if (c3335c.f9838i == 1) {
                            calculateItemDecorationsForChild(mo2715f2, f9786c);
                            addView(mo2715f2);
                        } else {
                            calculateItemDecorationsForChild(mo2715f2, f9786c);
                            addView(mo2715f2, i37);
                            i37++;
                        }
                        int i41 = i37;
                        int leftDecorationWidth2 = getLeftDecorationWidth(mo2715f2) + i31;
                        int rightDecorationWidth2 = i3 - getRightDecorationWidth(mo2715f2);
                        boolean z = this.f9793i;
                        if (!z) {
                            i9 = i36;
                            i10 = i38;
                            i11 = i39;
                            if (this.f9794j) {
                                this.f9796l.m2745v(mo2715f2, c2411b, z, leftDecorationWidth2, Math.round(bottomDecorationHeight) - mo2715f2.getMeasuredHeight(), mo2715f2.getMeasuredWidth() + leftDecorationWidth2, Math.round(bottomDecorationHeight));
                            } else {
                                this.f9796l.m2745v(mo2715f2, c2411b, z, leftDecorationWidth2, Math.round(topDecorationHeight2), mo2715f2.getMeasuredWidth() + leftDecorationWidth2, mo2715f2.getMeasuredHeight() + Math.round(topDecorationHeight2));
                            }
                        } else if (this.f9794j) {
                            i9 = i36;
                            i10 = i38;
                            i11 = i39;
                            this.f9796l.m2745v(mo2715f2, c2411b, z, rightDecorationWidth2 - mo2715f2.getMeasuredWidth(), Math.round(bottomDecorationHeight) - mo2715f2.getMeasuredHeight(), rightDecorationWidth2, Math.round(bottomDecorationHeight));
                        } else {
                            i9 = i36;
                            i10 = i38;
                            i11 = i39;
                            this.f9796l.m2745v(mo2715f2, c2411b, z, rightDecorationWidth2 - mo2715f2.getMeasuredWidth(), Math.round(topDecorationHeight2), rightDecorationWidth2, mo2715f2.getMeasuredHeight() + Math.round(topDecorationHeight2));
                        }
                        f9 = bottomDecorationHeight - ((getTopDecorationHeight(mo2715f2) + (mo2715f2.getMeasuredHeight() + ((ViewGroup.MarginLayoutParams) r8).bottomMargin)) + max2);
                        f8 = getBottomDecorationHeight(mo2715f2) + mo2715f2.getMeasuredHeight() + ((ViewGroup.MarginLayoutParams) r8).topMargin + max2 + topDecorationHeight2;
                        i37 = i41;
                    }
                    i36 = i9 + 1;
                    i20 = i7;
                    i21 = i8;
                    i35 = i10;
                    i34 = i11;
                }
                i4 = i20;
                i5 = i21;
                c3335c.f9832c += this.f9799o.f9838i;
                i6 = c2411b.f6424g;
            }
            i21 = i5 + i6;
            if (mo2718i || !this.f9793i) {
                c3335c.f9834e = (c2411b.f6424g * c3335c.f9838i) + c3335c.f9834e;
            } else {
                c3335c.f9834e -= c2411b.f6424g * c3335c.f9838i;
            }
            i20 = i4 - c2411b.f6424g;
            i19 = i2;
        }
        int i42 = i19;
        int i43 = i21;
        int i44 = c3335c.f9830a - i43;
        c3335c.f9830a = i44;
        int i45 = c3335c.f9835f;
        if (i45 != Integer.MIN_VALUE) {
            int i46 = i45 + i43;
            c3335c.f9835f = i46;
            if (i44 < 0) {
                c3335c.f9835f = i46 + i44;
            }
            m4173v(recycler, c3335c);
        }
        return i42 - c3335c.f9830a;
    }

    /* renamed from: n */
    public final View m4165n(int i2) {
        View m4170s = m4170s(0, getChildCount(), i2);
        if (m4170s == null) {
            return null;
        }
        int i3 = this.f9796l.f6438c[getPosition(m4170s)];
        if (i3 == -1) {
            return null;
        }
        return m4166o(m4170s, this.f9795k.get(i3));
    }

    /* renamed from: o */
    public final View m4166o(View view, C2411b c2411b) {
        boolean mo2718i = mo2718i();
        int i2 = c2411b.f6425h;
        for (int i3 = 1; i3 < i2; i3++) {
            View childAt = getChildAt(i3);
            if (childAt != null && childAt.getVisibility() != 8) {
                if (!this.f9793i || mo2718i) {
                    if (this.f9801q.getDecoratedStart(view) <= this.f9801q.getDecoratedStart(childAt)) {
                    }
                    view = childAt;
                } else {
                    if (this.f9801q.getDecoratedEnd(view) >= this.f9801q.getDecoratedEnd(childAt)) {
                    }
                    view = childAt;
                }
            }
        }
        return view;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAdapterChanged(RecyclerView.Adapter adapter, RecyclerView.Adapter adapter2) {
        removeAllViews();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAttachedToWindow(RecyclerView recyclerView) {
        super.onAttachedToWindow(recyclerView);
        this.f9810z = (View) recyclerView.getParent();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onDetachedFromWindow(RecyclerView recyclerView, RecyclerView.Recycler recycler) {
        super.onDetachedFromWindow(recyclerView, recycler);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsAdded(@NonNull RecyclerView recyclerView, int i2, int i3) {
        super.onItemsAdded(recyclerView, i2, i3);
        m4177z(i2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsMoved(@NonNull RecyclerView recyclerView, int i2, int i3, int i4) {
        super.onItemsMoved(recyclerView, i2, i3, i4);
        m4177z(Math.min(i2, i3));
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsRemoved(@NonNull RecyclerView recyclerView, int i2, int i3) {
        super.onItemsRemoved(recyclerView, i2, i3);
        m4177z(i2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsUpdated(@NonNull RecyclerView recyclerView, int i2, int i3, Object obj) {
        super.onItemsUpdated(recyclerView, i2, i3, obj);
        m4177z(i2);
    }

    /* JADX WARN: Removed duplicated region for block: B:111:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x0294  */
    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onLayoutChildren(androidx.recyclerview.widget.RecyclerView.Recycler r20, androidx.recyclerview.widget.RecyclerView.State r21) {
        /*
            Method dump skipped, instructions count: 1146
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.flexbox.FlexboxLayoutManager.onLayoutChildren(androidx.recyclerview.widget.RecyclerView$Recycler, androidx.recyclerview.widget.RecyclerView$State):void");
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutCompleted(RecyclerView.State state) {
        super.onLayoutCompleted(state);
        this.f9803s = null;
        this.f9804t = -1;
        this.f9805u = Integer.MIN_VALUE;
        this.f9787A = -1;
        C3334b.m4179b(this.f9800p);
        this.f9808x.clear();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof SavedState) {
            this.f9803s = (SavedState) parcelable;
            requestLayout();
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public Parcelable onSaveInstanceState() {
        SavedState savedState = this.f9803s;
        if (savedState != null) {
            return new SavedState(savedState, (C3333a) null);
        }
        SavedState savedState2 = new SavedState();
        if (getChildCount() > 0) {
            View childAt = getChildAt(0);
            savedState2.f9820c = getPosition(childAt);
            savedState2.f9821e = this.f9801q.getDecoratedStart(childAt) - this.f9801q.getStartAfterPadding();
        } else {
            savedState2.f9820c = -1;
        }
        return savedState2;
    }

    /* renamed from: p */
    public final View m4167p(int i2) {
        View m4170s = m4170s(getChildCount() - 1, -1, i2);
        if (m4170s == null) {
            return null;
        }
        return m4168q(m4170s, this.f9795k.get(this.f9796l.f6438c[getPosition(m4170s)]));
    }

    /* renamed from: q */
    public final View m4168q(View view, C2411b c2411b) {
        boolean mo2718i = mo2718i();
        int childCount = (getChildCount() - c2411b.f6425h) - 1;
        for (int childCount2 = getChildCount() - 2; childCount2 > childCount; childCount2--) {
            View childAt = getChildAt(childCount2);
            if (childAt != null && childAt.getVisibility() != 8) {
                if (!this.f9793i || mo2718i) {
                    if (this.f9801q.getDecoratedEnd(view) >= this.f9801q.getDecoratedEnd(childAt)) {
                    }
                    view = childAt;
                } else {
                    if (this.f9801q.getDecoratedStart(view) <= this.f9801q.getDecoratedStart(childAt)) {
                    }
                    view = childAt;
                }
            }
        }
        return view;
    }

    /* renamed from: r */
    public final View m4169r(int i2, int i3, boolean z) {
        int i4 = i2;
        int i5 = i3 > i4 ? 1 : -1;
        while (i4 != i3) {
            View childAt = getChildAt(i4);
            int paddingLeft = getPaddingLeft();
            int paddingTop = getPaddingTop();
            int width = getWidth() - getPaddingRight();
            int height = getHeight() - getPaddingBottom();
            int decoratedLeft = getDecoratedLeft(childAt) - ((ViewGroup.MarginLayoutParams) ((RecyclerView.LayoutParams) childAt.getLayoutParams())).leftMargin;
            int decoratedTop = getDecoratedTop(childAt) - ((ViewGroup.MarginLayoutParams) ((RecyclerView.LayoutParams) childAt.getLayoutParams())).topMargin;
            int decoratedRight = getDecoratedRight(childAt) + ((ViewGroup.MarginLayoutParams) ((RecyclerView.LayoutParams) childAt.getLayoutParams())).rightMargin;
            int decoratedBottom = getDecoratedBottom(childAt) + ((ViewGroup.MarginLayoutParams) ((RecyclerView.LayoutParams) childAt.getLayoutParams())).bottomMargin;
            boolean z2 = false;
            boolean z3 = paddingLeft <= decoratedLeft && width >= decoratedRight;
            boolean z4 = decoratedLeft >= width || decoratedRight >= paddingLeft;
            boolean z5 = paddingTop <= decoratedTop && height >= decoratedBottom;
            boolean z6 = decoratedTop >= height || decoratedBottom >= paddingTop;
            if (!z ? !(!z4 || !z6) : !(!z3 || !z5)) {
                z2 = true;
            }
            if (z2) {
                return childAt;
            }
            i4 += i5;
        }
        return null;
    }

    /* renamed from: s */
    public final View m4170s(int i2, int i3, int i4) {
        m4163l();
        View view = null;
        if (this.f9799o == null) {
            this.f9799o = new C3335c(null);
        }
        int startAfterPadding = this.f9801q.getStartAfterPadding();
        int endAfterPadding = this.f9801q.getEndAfterPadding();
        int i5 = i3 > i2 ? 1 : -1;
        View view2 = null;
        while (i2 != i3) {
            View childAt = getChildAt(i2);
            int position = getPosition(childAt);
            if (position >= 0 && position < i4) {
                if (((RecyclerView.LayoutParams) childAt.getLayoutParams()).isItemRemoved()) {
                    if (view2 == null) {
                        view2 = childAt;
                    }
                } else {
                    if (this.f9801q.getDecoratedStart(childAt) >= startAfterPadding && this.f9801q.getDecoratedEnd(childAt) <= endAfterPadding) {
                        return childAt;
                    }
                    if (view == null) {
                        view = childAt;
                    }
                }
            }
            i2 += i5;
        }
        return view != null ? view : view2;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (!mo2718i() || (this.f9790f == 0 && mo2718i())) {
            int m4171t = m4171t(i2, recycler, state);
            this.f9808x.clear();
            return m4171t;
        }
        int m4172u = m4172u(i2);
        this.f9800p.f9825d += m4172u;
        this.f9802r.offsetChildren(-m4172u);
        return m4172u;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void scrollToPosition(int i2) {
        this.f9804t = i2;
        this.f9805u = Integer.MIN_VALUE;
        SavedState savedState = this.f9803s;
        if (savedState != null) {
            savedState.f9820c = -1;
        }
        requestLayout();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (mo2718i() || (this.f9790f == 0 && !mo2718i())) {
            int m4171t = m4171t(i2, recycler, state);
            this.f9808x.clear();
            return m4171t;
        }
        int m4172u = m4172u(i2);
        this.f9800p.f9825d += m4172u;
        this.f9802r.offsetChildren(-m4172u);
        return m4172u;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public void setFlexLines(List<C2411b> list) {
        this.f9795k = list;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void smoothScrollToPosition(RecyclerView recyclerView, RecyclerView.State state, int i2) {
        LinearSmoothScroller linearSmoothScroller = new LinearSmoothScroller(recyclerView.getContext());
        linearSmoothScroller.setTargetPosition(i2);
        startSmoothScroll(linearSmoothScroller);
    }

    /* renamed from: t */
    public final int m4171t(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        int i3;
        if (getChildCount() == 0 || i2 == 0) {
            return 0;
        }
        m4163l();
        this.f9799o.f9839j = true;
        boolean z = !mo2718i() && this.f9793i;
        int i4 = (!z ? i2 > 0 : i2 < 0) ? -1 : 1;
        int abs = Math.abs(i2);
        this.f9799o.f9838i = i4;
        boolean mo2718i = mo2718i();
        int makeMeasureSpec = View.MeasureSpec.makeMeasureSpec(getWidth(), getWidthMode());
        int makeMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(getHeight(), getHeightMode());
        boolean z2 = !mo2718i && this.f9793i;
        if (i4 == 1) {
            View childAt = getChildAt(getChildCount() - 1);
            this.f9799o.f9834e = this.f9801q.getDecoratedEnd(childAt);
            int position = getPosition(childAt);
            View m4168q = m4168q(childAt, this.f9795k.get(this.f9796l.f6438c[position]));
            C3335c c3335c = this.f9799o;
            c3335c.f9837h = 1;
            int i5 = position + 1;
            c3335c.f9833d = i5;
            int[] iArr = this.f9796l.f6438c;
            if (iArr.length <= i5) {
                c3335c.f9832c = -1;
            } else {
                c3335c.f9832c = iArr[i5];
            }
            if (z2) {
                c3335c.f9834e = this.f9801q.getDecoratedStart(m4168q);
                this.f9799o.f9835f = this.f9801q.getStartAfterPadding() + (-this.f9801q.getDecoratedStart(m4168q));
                C3335c c3335c2 = this.f9799o;
                int i6 = c3335c2.f9835f;
                if (i6 < 0) {
                    i6 = 0;
                }
                c3335c2.f9835f = i6;
            } else {
                c3335c.f9834e = this.f9801q.getDecoratedEnd(m4168q);
                this.f9799o.f9835f = this.f9801q.getDecoratedEnd(m4168q) - this.f9801q.getEndAfterPadding();
            }
            int i7 = this.f9799o.f9832c;
            if ((i7 == -1 || i7 > this.f9795k.size() - 1) && this.f9799o.f9833d <= getFlexItemCount()) {
                int i8 = abs - this.f9799o.f9835f;
                this.f9788B.m2750a();
                if (i8 > 0) {
                    if (mo2718i) {
                        this.f9796l.m2725b(this.f9788B, makeMeasureSpec, makeMeasureSpec2, i8, this.f9799o.f9833d, -1, this.f9795k);
                    } else {
                        this.f9796l.m2725b(this.f9788B, makeMeasureSpec2, makeMeasureSpec, i8, this.f9799o.f9833d, -1, this.f9795k);
                    }
                    this.f9796l.m2731h(makeMeasureSpec, makeMeasureSpec2, this.f9799o.f9833d);
                    this.f9796l.m2722A(this.f9799o.f9833d);
                }
            }
        } else {
            View childAt2 = getChildAt(0);
            this.f9799o.f9834e = this.f9801q.getDecoratedStart(childAt2);
            int position2 = getPosition(childAt2);
            View m4166o = m4166o(childAt2, this.f9795k.get(this.f9796l.f6438c[position2]));
            C3335c c3335c3 = this.f9799o;
            c3335c3.f9837h = 1;
            int i9 = this.f9796l.f6438c[position2];
            if (i9 == -1) {
                i9 = 0;
            }
            if (i9 > 0) {
                this.f9799o.f9833d = position2 - this.f9795k.get(i9 - 1).f6425h;
            } else {
                c3335c3.f9833d = -1;
            }
            C3335c c3335c4 = this.f9799o;
            c3335c4.f9832c = i9 > 0 ? i9 - 1 : 0;
            if (z2) {
                c3335c4.f9834e = this.f9801q.getDecoratedEnd(m4166o);
                this.f9799o.f9835f = this.f9801q.getDecoratedEnd(m4166o) - this.f9801q.getEndAfterPadding();
                C3335c c3335c5 = this.f9799o;
                int i10 = c3335c5.f9835f;
                if (i10 < 0) {
                    i10 = 0;
                }
                c3335c5.f9835f = i10;
            } else {
                c3335c4.f9834e = this.f9801q.getDecoratedStart(m4166o);
                this.f9799o.f9835f = this.f9801q.getStartAfterPadding() + (-this.f9801q.getDecoratedStart(m4166o));
            }
        }
        C3335c c3335c6 = this.f9799o;
        int i11 = c3335c6.f9835f;
        c3335c6.f9830a = abs - i11;
        int m4164m = m4164m(recycler, state, c3335c6) + i11;
        if (m4164m < 0) {
            return 0;
        }
        if (z) {
            if (abs > m4164m) {
                i3 = (-i4) * m4164m;
            }
            i3 = i2;
        } else {
            if (abs > m4164m) {
                i3 = i4 * m4164m;
            }
            i3 = i2;
        }
        this.f9801q.offsetChildren(-i3);
        this.f9799o.f9836g = i3;
        return i3;
    }

    /* renamed from: u */
    public final int m4172u(int i2) {
        int i3;
        if (getChildCount() == 0 || i2 == 0) {
            return 0;
        }
        m4163l();
        boolean mo2718i = mo2718i();
        View view = this.f9810z;
        int width = mo2718i ? view.getWidth() : view.getHeight();
        int width2 = mo2718i ? getWidth() : getHeight();
        if (getLayoutDirection() == 1) {
            int abs = Math.abs(i2);
            if (i2 < 0) {
                return -Math.min((width2 + this.f9800p.f9825d) - width, abs);
            }
            i3 = this.f9800p.f9825d;
            if (i3 + i2 <= 0) {
                return i2;
            }
        } else {
            if (i2 > 0) {
                return Math.min((width2 - this.f9800p.f9825d) - width, i2);
            }
            i3 = this.f9800p.f9825d;
            if (i3 + i2 >= 0) {
                return i2;
            }
        }
        return -i3;
    }

    /* renamed from: v */
    public final void m4173v(RecyclerView.Recycler recycler, C3335c c3335c) {
        int childCount;
        if (c3335c.f9839j) {
            int i2 = -1;
            if (c3335c.f9838i != -1) {
                if (c3335c.f9835f >= 0 && (childCount = getChildCount()) != 0) {
                    int i3 = this.f9796l.f6438c[getPosition(getChildAt(0))];
                    if (i3 == -1) {
                        return;
                    }
                    C2411b c2411b = this.f9795k.get(i3);
                    int i4 = 0;
                    while (true) {
                        if (i4 >= childCount) {
                            break;
                        }
                        View childAt = getChildAt(i4);
                        int i5 = c3335c.f9835f;
                        if (!(mo2718i() || !this.f9793i ? this.f9801q.getDecoratedEnd(childAt) <= i5 : this.f9801q.getEnd() - this.f9801q.getDecoratedStart(childAt) <= i5)) {
                            break;
                        }
                        if (c2411b.f6433p == getPosition(childAt)) {
                            if (i3 >= this.f9795k.size() - 1) {
                                i2 = i4;
                                break;
                            } else {
                                i3 += c3335c.f9838i;
                                c2411b = this.f9795k.get(i3);
                                i2 = i4;
                            }
                        }
                        i4++;
                    }
                    while (i2 >= 0) {
                        removeAndRecycleViewAt(i2, recycler);
                        i2--;
                    }
                    return;
                }
                return;
            }
            if (c3335c.f9835f < 0) {
                return;
            }
            this.f9801q.getEnd();
            int childCount2 = getChildCount();
            if (childCount2 == 0) {
                return;
            }
            int i6 = childCount2 - 1;
            int i7 = this.f9796l.f6438c[getPosition(getChildAt(i6))];
            if (i7 == -1) {
                return;
            }
            C2411b c2411b2 = this.f9795k.get(i7);
            int i8 = i6;
            while (true) {
                if (i8 < 0) {
                    break;
                }
                View childAt2 = getChildAt(i8);
                int i9 = c3335c.f9835f;
                if (!(mo2718i() || !this.f9793i ? this.f9801q.getDecoratedStart(childAt2) >= this.f9801q.getEnd() - i9 : this.f9801q.getDecoratedEnd(childAt2) <= i9)) {
                    break;
                }
                if (c2411b2.f6432o == getPosition(childAt2)) {
                    if (i7 <= 0) {
                        childCount2 = i8;
                        break;
                    } else {
                        i7 += c3335c.f9838i;
                        c2411b2 = this.f9795k.get(i7);
                        childCount2 = i8;
                    }
                }
                i8--;
            }
            while (i6 >= childCount2) {
                removeAndRecycleViewAt(i6, recycler);
                i6--;
            }
        }
    }

    /* renamed from: w */
    public final void m4174w() {
        int heightMode = mo2718i() ? getHeightMode() : getWidthMode();
        this.f9799o.f9831b = heightMode == 0 || heightMode == Integer.MIN_VALUE;
    }

    /* renamed from: x */
    public void m4175x(int i2) {
        if (this.f9789e != i2) {
            removeAllViews();
            this.f9789e = i2;
            this.f9801q = null;
            this.f9802r = null;
            m4162k();
            requestLayout();
        }
    }

    /* renamed from: y */
    public void m4176y(int i2) {
        if (i2 == 2) {
            throw new UnsupportedOperationException("wrap_reverse is not supported in FlexboxLayoutManager");
        }
        int i3 = this.f9790f;
        if (i3 != i2) {
            if (i3 == 0 || i2 == 0) {
                removeAllViews();
                m4162k();
            }
            this.f9790f = i2;
            this.f9801q = null;
            this.f9802r = null;
            requestLayout();
        }
    }

    /* renamed from: z */
    public final void m4177z(int i2) {
        if (i2 >= findLastVisibleItemPosition()) {
            return;
        }
        int childCount = getChildCount();
        this.f9796l.m2733j(childCount);
        this.f9796l.m2734k(childCount);
        this.f9796l.m2732i(childCount);
        if (i2 >= this.f9796l.f6438c.length) {
            return;
        }
        this.f9787A = i2;
        View childAt = getChildAt(0);
        if (childAt == null) {
            return;
        }
        this.f9804t = getPosition(childAt);
        if (mo2718i() || !this.f9793i) {
            this.f9805u = this.f9801q.getDecoratedStart(childAt) - this.f9801q.getStartAfterPadding();
        } else {
            this.f9805u = this.f9801q.getEndPadding() + this.f9801q.getDecoratedEnd(childAt);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsUpdated(@NonNull RecyclerView recyclerView, int i2, int i3) {
        super.onItemsUpdated(recyclerView, i2, i3);
        m4177z(i2);
    }

    public static class LayoutParams extends RecyclerView.LayoutParams implements FlexItem {
        public static final Parcelable.Creator<LayoutParams> CREATOR = new C3331a();

        /* renamed from: c */
        public float f9811c;

        /* renamed from: e */
        public float f9812e;

        /* renamed from: f */
        public int f9813f;

        /* renamed from: g */
        public float f9814g;

        /* renamed from: h */
        public int f9815h;

        /* renamed from: i */
        public int f9816i;

        /* renamed from: j */
        public int f9817j;

        /* renamed from: k */
        public int f9818k;

        /* renamed from: l */
        public boolean f9819l;

        /* renamed from: com.google.android.flexbox.FlexboxLayoutManager$LayoutParams$a */
        public static class C3331a implements Parcelable.Creator<LayoutParams> {
            @Override // android.os.Parcelable.Creator
            public LayoutParams createFromParcel(Parcel parcel) {
                return new LayoutParams(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public LayoutParams[] newArray(int i2) {
                return new LayoutParams[i2];
            }
        }

        public LayoutParams(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            this.f9811c = 0.0f;
            this.f9812e = 1.0f;
            this.f9813f = -1;
            this.f9814g = -1.0f;
            this.f9817j = ViewCompat.MEASURED_SIZE_MASK;
            this.f9818k = ViewCompat.MEASURED_SIZE_MASK;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: a */
        public int mo4134a() {
            return this.f9813f;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: c */
        public float mo4135c() {
            return this.f9812e;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: f */
        public int mo4136f() {
            return this.f9815h;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: g */
        public void mo4137g(int i2) {
            this.f9815h = i2;
        }

        @Override // com.google.android.flexbox.FlexItem
        public int getHeight() {
            return ((ViewGroup.MarginLayoutParams) this).height;
        }

        @Override // com.google.android.flexbox.FlexItem
        public int getOrder() {
            return 1;
        }

        @Override // com.google.android.flexbox.FlexItem
        public int getWidth() {
            return ((ViewGroup.MarginLayoutParams) this).width;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: h */
        public int mo4138h() {
            return ((ViewGroup.MarginLayoutParams) this).bottomMargin;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: i */
        public int mo4139i() {
            return ((ViewGroup.MarginLayoutParams) this).leftMargin;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: j */
        public int mo4140j() {
            return ((ViewGroup.MarginLayoutParams) this).topMargin;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: l */
        public void mo4141l(int i2) {
            this.f9816i = i2;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: m */
        public float mo4142m() {
            return this.f9811c;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: n */
        public float mo4143n() {
            return this.f9814g;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: p */
        public int mo4144p() {
            return ((ViewGroup.MarginLayoutParams) this).rightMargin;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: r */
        public int mo4145r() {
            return this.f9816i;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: s */
        public boolean mo4146s() {
            return this.f9819l;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: t */
        public int mo4147t() {
            return this.f9818k;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: v */
        public int mo4148v() {
            return this.f9817j;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeFloat(this.f9811c);
            parcel.writeFloat(this.f9812e);
            parcel.writeInt(this.f9813f);
            parcel.writeFloat(this.f9814g);
            parcel.writeInt(this.f9815h);
            parcel.writeInt(this.f9816i);
            parcel.writeInt(this.f9817j);
            parcel.writeInt(this.f9818k);
            parcel.writeByte(this.f9819l ? (byte) 1 : (byte) 0);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).bottomMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).leftMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).rightMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).topMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).height);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).width);
        }

        public LayoutParams(int i2, int i3) {
            super(i2, i3);
            this.f9811c = 0.0f;
            this.f9812e = 1.0f;
            this.f9813f = -1;
            this.f9814g = -1.0f;
            this.f9817j = ViewCompat.MEASURED_SIZE_MASK;
            this.f9818k = ViewCompat.MEASURED_SIZE_MASK;
        }

        public LayoutParams(Parcel parcel) {
            super(-2, -2);
            this.f9811c = 0.0f;
            this.f9812e = 1.0f;
            this.f9813f = -1;
            this.f9814g = -1.0f;
            this.f9817j = ViewCompat.MEASURED_SIZE_MASK;
            this.f9818k = ViewCompat.MEASURED_SIZE_MASK;
            this.f9811c = parcel.readFloat();
            this.f9812e = parcel.readFloat();
            this.f9813f = parcel.readInt();
            this.f9814g = parcel.readFloat();
            this.f9815h = parcel.readInt();
            this.f9816i = parcel.readInt();
            this.f9817j = parcel.readInt();
            this.f9818k = parcel.readInt();
            this.f9819l = parcel.readByte() != 0;
            ((ViewGroup.MarginLayoutParams) this).bottomMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).leftMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).rightMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).topMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).height = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).width = parcel.readInt();
        }
    }

    public FlexboxLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        RecyclerView.LayoutManager.Properties properties = RecyclerView.LayoutManager.getProperties(context, attributeSet, i2, i3);
        int i4 = properties.orientation;
        if (i4 != 0) {
            if (i4 == 1) {
                if (properties.reverseLayout) {
                    m4175x(3);
                } else {
                    m4175x(2);
                }
            }
        } else if (properties.reverseLayout) {
            m4175x(1);
        } else {
            m4175x(0);
        }
        m4176y(1);
        if (this.f9791g != 4) {
            removeAllViews();
            m4162k();
            this.f9791g = 4;
            requestLayout();
        }
        setAutoMeasureEnabled(true);
        this.f9809y = context;
    }
}
