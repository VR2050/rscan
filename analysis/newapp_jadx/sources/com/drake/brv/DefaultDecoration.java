package com.drake.brv;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import com.drake.brv.annotaion.DividerOrientation;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt__MathJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5310d1 = {"\u0000\u008a\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u000e\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010!\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u0015\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u000e\u0018\u00002\u00020\u0001:\u0001WB\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0014\u00101\u001a\u0002022\f\b\u0001\u00103\u001a\u000204\"\u00020\u0017J\u0010\u00105\u001a\u0002022\u0006\u00106\u001a\u00020/H\u0002J \u00107\u001a\u0002022\u0006\u00108\u001a\u0002092\u0006\u0010:\u001a\u00020;2\u0006\u0010<\u001a\u00020\bH\u0002J \u0010=\u001a\u0002022\u0006\u00108\u001a\u0002092\u0006\u0010:\u001a\u00020;2\u0006\u0010<\u001a\u00020\bH\u0002J \u0010>\u001a\u0002022\u0006\u00108\u001a\u0002092\u0006\u0010:\u001a\u00020;2\u0006\u0010<\u001a\u00020\bH\u0002J(\u0010?\u001a\u0002022\u0006\u0010@\u001a\u00020A2\u0006\u0010B\u001a\u00020C2\u0006\u0010:\u001a\u00020;2\u0006\u0010D\u001a\u00020EH\u0016J \u0010F\u001a\u0002022\u0006\u00108\u001a\u0002092\u0006\u0010:\u001a\u00020;2\u0006\u0010D\u001a\u00020EH\u0016J#\u0010\u0019\u001a\u0002022\u001b\u0010G\u001a\u0017\u0012\b\u0012\u00060\u001bR\u00020\u001c\u0012\u0004\u0012\u00020\b0\u001a¢\u0006\u0002\b\u001dJ\u0010\u0010H\u001a\u0002022\b\b\u0001\u0010I\u001a\u00020\u0017J\u000e\u0010H\u001a\u0002022\u0006\u0010I\u001a\u00020JJ\u0010\u0010K\u001a\u0002022\b\b\u0001\u0010I\u001a\u00020\u0017J\u001a\u0010L\u001a\u0002022\b\b\u0002\u0010M\u001a\u00020\u00172\b\b\u0002\u0010N\u001a\u00020\bJ\u000e\u0010O\u001a\u0002022\u0006\u0010P\u001a\u00020\u0006J\u0010\u0010O\u001a\u0002022\b\b\u0001\u0010Q\u001a\u00020\u0017J8\u0010R\u001a\u0002022\b\b\u0002\u0010S\u001a\u00020\u00172\b\b\u0002\u0010T\u001a\u00020\u00172\b\b\u0002\u0010N\u001a\u00020\b2\b\b\u0002\u0010U\u001a\u00020\b2\b\b\u0002\u0010V\u001a\u00020\bR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0005\u001a\u0004\u0018\u00010\u0006X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010\u0007\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR\u001a\u0010\r\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\n\"\u0004\b\u000f\u0010\fR$\u0010\u0011\u001a\u00020\b2\u0006\u0010\u0010\u001a\u00020\b8F@FX\u0086\u000e¢\u0006\f\u001a\u0004\b\u0012\u0010\n\"\u0004\b\u0013\u0010\fR\u000e\u0010\u0014\u001a\u00020\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0015\u001a\u00020\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0016\u001a\u00020\u0017X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0018\u001a\u00020\u0017X\u0082\u000e¢\u0006\u0002\n\u0000R%\u0010\u0019\u001a\u0019\u0012\b\u0012\u00060\u001bR\u00020\u001c\u0012\u0004\u0012\u00020\b\u0018\u00010\u001a¢\u0006\u0002\b\u001dX\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010\u001e\u001a\u00020\u001fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b \u0010!\"\u0004\b\"\u0010#R\u000e\u0010$\u001a\u00020\u0017X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010%\u001a\u00020\bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b&\u0010\n\"\u0004\b'\u0010\fR\"\u0010(\u001a\n\u0012\u0004\u0012\u00020\u0017\u0018\u00010)X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b*\u0010+\"\u0004\b,\u0010-R\u0018\u0010.\u001a\u00020\b*\u00020/8BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b.\u00100¨\u0006X"}, m5311d2 = {"Lcom/drake/brv/DefaultDecoration;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "divider", "Landroid/graphics/drawable/Drawable;", "endVisible", "", "getEndVisible", "()Z", "setEndVisible", "(Z)V", "expandVisible", "getExpandVisible", "setExpandVisible", "value", "includeVisible", "getIncludeVisible", "setIncludeVisible", "marginBaseItemEnd", "marginBaseItemStart", "marginEnd", "", "marginStart", "onEnabled", "Lkotlin/Function1;", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "Lcom/drake/brv/BindingAdapter;", "Lkotlin/ExtensionFunctionType;", "orientation", "Lcom/drake/brv/annotaion/DividerOrientation;", "getOrientation", "()Lcom/drake/brv/annotaion/DividerOrientation;", "setOrientation", "(Lcom/drake/brv/annotaion/DividerOrientation;)V", "size", "startVisible", "getStartVisible", "setStartVisible", "typePool", "", "getTypePool", "()Ljava/util/List;", "setTypePool", "(Ljava/util/List;)V", "isReverseLayout", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "(Landroidx/recyclerview/widget/RecyclerView$LayoutManager;)Z", "addType", "", "typeArray", "", "adjustOrientation", "layoutManager", "drawGrid", "canvas", "Landroid/graphics/Canvas;", "parent", "Landroidx/recyclerview/widget/RecyclerView;", "reverseLayout", "drawHorizontal", "drawVertical", "getItemOffsets", "outRect", "Landroid/graphics/Rect;", "view", "Landroid/view/View;", "state", "Landroidx/recyclerview/widget/RecyclerView$State;", "onDraw", "block", "setColor", "color", "", "setColorRes", "setDivider", "width", "dp", "setDrawable", "drawable", "drawableRes", "setMargin", "start", "end", "baseItemStart", "baseItemEnd", "Edge", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public final class DefaultDecoration extends RecyclerView.ItemDecoration {

    /* renamed from: a */
    @NotNull
    public final Context f8938a;

    /* renamed from: b */
    @NotNull
    public DividerOrientation f8939b;

    /* renamed from: c */
    public int f8940c;

    /* renamed from: d */
    @Nullable
    public Drawable f8941d;

    @Metadata(m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0016\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0086\b\u0018\u0000 \u001d2\u00020\u0001:\u0001\u001dB-\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0005\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0006\u001a\u00020\u0003¢\u0006\u0002\u0010\u0007J\t\u0010\u0012\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0013\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0014\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0015\u001a\u00020\u0003HÆ\u0003J1\u0010\u0016\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00032\b\b\u0002\u0010\u0006\u001a\u00020\u0003HÆ\u0001J\u0013\u0010\u0017\u001a\u00020\u00032\b\u0010\u0018\u001a\u0004\u0018\u00010\u0001HÖ\u0003J\t\u0010\u0019\u001a\u00020\u001aHÖ\u0001J\t\u0010\u001b\u001a\u00020\u001cHÖ\u0001R\u001a\u0010\u0006\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\b\u0010\t\"\u0004\b\n\u0010\u000bR\u001a\u0010\u0002\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\f\u0010\t\"\u0004\b\r\u0010\u000bR\u001a\u0010\u0005\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\t\"\u0004\b\u000f\u0010\u000bR\u001a\u0010\u0004\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0010\u0010\t\"\u0004\b\u0011\u0010\u000b¨\u0006\u001e"}, m5311d2 = {"Lcom/drake/brv/DefaultDecoration$Edge;", "", "left", "", "top", "right", "bottom", "(ZZZZ)V", "getBottom", "()Z", "setBottom", "(Z)V", "getLeft", "setLeft", "getRight", "setRight", "getTop", "setTop", "component1", "component2", "component3", "component4", "copy", "equals", "other", "hashCode", "", "toString", "", "Companion", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.DefaultDecoration$a */
    public static final /* data */ class C3236a {

        /* renamed from: a */
        public boolean f8942a;

        /* renamed from: b */
        public boolean f8943b;

        /* renamed from: c */
        public boolean f8944c;

        /* renamed from: d */
        public boolean f8945d;

        public C3236a() {
            this(false, false, false, false, 15);
        }

        public C3236a(boolean z, boolean z2, boolean z3, boolean z4, int i2) {
            z = (i2 & 1) != 0 ? false : z;
            z2 = (i2 & 2) != 0 ? false : z2;
            z3 = (i2 & 4) != 0 ? false : z3;
            z4 = (i2 & 8) != 0 ? false : z4;
            this.f8942a = z;
            this.f8943b = z2;
            this.f8944c = z3;
            this.f8945d = z4;
        }

        @NotNull
        /* renamed from: a */
        public static final C3236a m3947a(int i2, @NotNull RecyclerView.LayoutManager layoutManager, boolean z) {
            Intrinsics.checkNotNullParameter(layoutManager, "layoutManager");
            int i3 = i2 + 1;
            int itemCount = layoutManager.getItemCount();
            C3236a c3236a = new C3236a(false, false, false, false, 15);
            if (layoutManager instanceof StaggeredGridLayoutManager) {
                StaggeredGridLayoutManager staggeredGridLayoutManager = (StaggeredGridLayoutManager) layoutManager;
                int spanCount = staggeredGridLayoutManager.getSpanCount();
                View findViewByPosition = layoutManager.findViewByPosition(i2);
                if (findViewByPosition != null) {
                    ViewGroup.LayoutParams layoutParams = findViewByPosition.getLayoutParams();
                    Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type androidx.recyclerview.widget.StaggeredGridLayoutManager.LayoutParams");
                    int spanIndex = ((StaggeredGridLayoutManager.LayoutParams) layoutParams).getSpanIndex() + 1;
                    if (staggeredGridLayoutManager.getOrientation() == 1) {
                        c3236a.f8942a = spanIndex == 1;
                        c3236a.f8944c = spanIndex == spanCount;
                        if (!z ? i3 <= spanCount : i3 > itemCount - spanCount) {
                            r3 = true;
                        }
                        c3236a.f8943b = r3;
                        if (!z ? i3 > itemCount - spanCount : i3 <= spanCount) {
                            r9 = true;
                        }
                        c3236a.f8945d = r9;
                    } else {
                        c3236a.f8942a = i3 <= spanCount;
                        c3236a.f8944c = i3 > itemCount - spanCount;
                        if (!z ? spanIndex == 1 : spanIndex == spanCount) {
                            r3 = true;
                        }
                        c3236a.f8943b = r3;
                        if (!z ? spanIndex == spanCount : spanIndex == 1) {
                            r9 = true;
                        }
                        c3236a.f8945d = r9;
                    }
                }
            } else if (layoutManager instanceof GridLayoutManager) {
                GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
                GridLayoutManager.SpanSizeLookup spanSizeLookup = gridLayoutManager.getSpanSizeLookup();
                int spanCount2 = gridLayoutManager.getSpanCount();
                int spanGroupIndex = spanSizeLookup.getSpanGroupIndex(i2, spanCount2);
                int spanGroupIndex2 = spanSizeLookup.getSpanGroupIndex(itemCount - 1, spanCount2);
                int spanIndex2 = spanSizeLookup.getSpanIndex(i2, spanCount2) + 1;
                int spanSize = spanSizeLookup.getSpanSize(i2);
                if (gridLayoutManager.getOrientation() == 1) {
                    c3236a.f8942a = spanIndex2 == 1;
                    c3236a.f8944c = (spanIndex2 + spanSize) - 1 == spanCount2;
                    if (!z ? !(i3 > spanCount2 || spanGroupIndex != spanSizeLookup.getSpanGroupIndex(i2 - 1, spanCount2)) : spanGroupIndex == spanGroupIndex2) {
                        r3 = true;
                    }
                    c3236a.f8943b = r3;
                    if (!z ? spanGroupIndex == spanGroupIndex2 : !(i3 > spanCount2 || spanGroupIndex != spanSizeLookup.getSpanGroupIndex(i2 - 1, spanCount2))) {
                        r9 = true;
                    }
                    c3236a.f8945d = r9;
                } else {
                    c3236a.f8942a = spanGroupIndex == 0;
                    c3236a.f8944c = spanGroupIndex == spanGroupIndex2;
                    if (!z ? spanIndex2 == 1 : (spanIndex2 + spanSize) - 1 == spanCount2) {
                        r3 = true;
                    }
                    c3236a.f8943b = r3;
                    if (!z ? (spanIndex2 + spanSize) - 1 == spanCount2 : spanIndex2 == 1) {
                        r9 = true;
                    }
                    c3236a.f8945d = r9;
                }
            } else if (layoutManager instanceof LinearLayoutManager) {
                if (((LinearLayoutManager) layoutManager).getOrientation() == 1) {
                    c3236a.f8942a = true;
                    c3236a.f8944c = true;
                    if (!z ? i3 == 1 : i3 == itemCount) {
                        r3 = true;
                    }
                    c3236a.f8943b = r3;
                    if (!z ? i3 == itemCount : i3 == 1) {
                        r9 = true;
                    }
                    c3236a.f8945d = r9;
                } else {
                    c3236a.f8942a = i3 == 1;
                    c3236a.f8944c = i3 == itemCount;
                    c3236a.f8943b = true;
                    c3236a.f8945d = true;
                }
            }
            return c3236a;
        }

        public boolean equals(@Nullable Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof C3236a)) {
                return false;
            }
            C3236a c3236a = (C3236a) other;
            return this.f8942a == c3236a.f8942a && this.f8943b == c3236a.f8943b && this.f8944c == c3236a.f8944c && this.f8945d == c3236a.f8945d;
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Type inference failed for: r0v1, types: [int] */
        /* JADX WARN: Type inference failed for: r0v8 */
        /* JADX WARN: Type inference failed for: r0v9 */
        /* JADX WARN: Type inference failed for: r2v0, types: [boolean] */
        /* JADX WARN: Type inference failed for: r2v2, types: [boolean] */
        public int hashCode() {
            boolean z = this.f8942a;
            ?? r0 = z;
            if (z) {
                r0 = 1;
            }
            int i2 = r0 * 31;
            ?? r2 = this.f8943b;
            int i3 = r2;
            if (r2 != 0) {
                i3 = 1;
            }
            int i4 = (i2 + i3) * 31;
            ?? r22 = this.f8944c;
            int i5 = r22;
            if (r22 != 0) {
                i5 = 1;
            }
            int i6 = (i4 + i5) * 31;
            boolean z2 = this.f8945d;
            return i6 + (z2 ? 1 : z2 ? 1 : 0);
        }

        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("Edge(left=");
            m586H.append(this.f8942a);
            m586H.append(", top=");
            m586H.append(this.f8943b);
            m586H.append(", right=");
            m586H.append(this.f8944c);
            m586H.append(", bottom=");
            m586H.append(this.f8945d);
            m586H.append(')');
            return m586H.toString();
        }
    }

    public DefaultDecoration(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.f8938a = context;
        this.f8939b = DividerOrientation.HORIZONTAL;
        this.f8940c = 1;
    }

    /* renamed from: c */
    public static void m3943c(DefaultDecoration defaultDecoration, int i2, boolean z, int i3) {
        if ((i3 & 1) != 0) {
            i2 = 1;
        }
        if ((i3 & 2) != 0) {
            z = false;
        }
        if (z) {
            defaultDecoration.f8940c = MathKt__MathJVMKt.roundToInt(defaultDecoration.f8938a.getResources().getDisplayMetrics().density * i2);
        } else {
            defaultDecoration.f8940c = i2;
        }
    }

    /* renamed from: a */
    public final void m3944a(RecyclerView.LayoutManager layoutManager) {
        boolean z;
        if ((layoutManager instanceof GridLayoutManager) || !((z = layoutManager instanceof LinearLayoutManager))) {
            if (layoutManager instanceof StaggeredGridLayoutManager) {
                this.f8939b = DividerOrientation.GRID;
            }
        } else {
            LinearLayoutManager linearLayoutManager = z ? (LinearLayoutManager) layoutManager : null;
            boolean z2 = false;
            if (linearLayoutManager != null && linearLayoutManager.getOrientation() == 1) {
                z2 = true;
            }
            this.f8939b = z2 ? DividerOrientation.HORIZONTAL : DividerOrientation.VERTICAL;
        }
    }

    /* renamed from: b */
    public final boolean m3945b(RecyclerView.LayoutManager layoutManager) {
        if (layoutManager instanceof LinearLayoutManager) {
            return ((LinearLayoutManager) layoutManager).getReverseLayout();
        }
        if (layoutManager instanceof StaggeredGridLayoutManager) {
            return ((StaggeredGridLayoutManager) layoutManager).getReverseLayout();
        }
        return false;
    }

    /* renamed from: d */
    public final void m3946d(@NotNull DividerOrientation dividerOrientation) {
        Intrinsics.checkNotNullParameter(dividerOrientation, "<set-?>");
        this.f8939b = dividerOrientation;
    }

    /* JADX WARN: Code restructure failed: missing block: B:86:0x01b9, code lost:
    
        r9 = 0;
     */
    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void getItemOffsets(@org.jetbrains.annotations.NotNull android.graphics.Rect r17, @org.jetbrains.annotations.NotNull android.view.View r18, @org.jetbrains.annotations.NotNull androidx.recyclerview.widget.RecyclerView r19, @org.jetbrains.annotations.NotNull androidx.recyclerview.widget.RecyclerView.State r20) {
        /*
            Method dump skipped, instructions count: 494
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.drake.brv.DefaultDecoration.getItemOffsets(android.graphics.Rect, android.view.View, androidx.recyclerview.widget.RecyclerView, androidx.recyclerview.widget.RecyclerView$State):void");
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(@NotNull Canvas canvas, @NotNull RecyclerView parent, @NotNull RecyclerView.State state) {
        int i2;
        int height;
        int i3;
        Drawable drawable;
        int width;
        int i4;
        int i5;
        int i6;
        int i7;
        int intrinsicHeight;
        int i8;
        int i9;
        DividerOrientation dividerOrientation = DividerOrientation.GRID;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(state, "state");
        RecyclerView.LayoutManager layoutManager = parent.getLayoutManager();
        if (layoutManager == null || this.f8941d == null) {
            return;
        }
        m3944a(layoutManager);
        boolean m3945b = m3945b(layoutManager);
        int ordinal = this.f8939b.ordinal();
        int i10 = -1;
        if (ordinal == 0) {
            canvas.save();
            if (parent.getClipToPadding()) {
                i2 = 0;
                i3 = parent.getPaddingTop() + 0;
                height = (parent.getHeight() - parent.getPaddingBottom()) - 0;
            } else {
                i2 = 0;
                height = parent.getHeight() + 0;
                i3 = 0;
            }
            int childCount = parent.getChildCount();
            while (i2 < childCount) {
                int i11 = i2 + 1;
                View childAt = parent.getChildAt(i2);
                int childAdapterPosition = parent.getChildAdapterPosition(childAt);
                RecyclerView.LayoutManager layoutManager2 = parent.getLayoutManager();
                if (layoutManager2 == null) {
                    return;
                }
                C3236a m3947a = C3236a.m3947a(childAdapterPosition, layoutManager2, m3945b);
                if ((this.f8939b == dividerOrientation || !m3947a.f8944c) && (drawable = this.f8941d) != null) {
                    parent.getDecoratedBoundsWithMargins(childAt, new Rect());
                    if (drawable.getIntrinsicWidth() != -1) {
                        drawable.getIntrinsicWidth();
                    }
                    int roundToInt = MathKt__MathJVMKt.roundToInt(childAt.getTranslationX() + r11.right);
                    drawable.setBounds(roundToInt - (drawable.getIntrinsicWidth() == -1 ? this.f8940c : drawable.getIntrinsicWidth()), i3, roundToInt, height);
                    drawable.draw(canvas);
                }
                i2 = i11;
            }
            canvas.restore();
            return;
        }
        if (ordinal == 1) {
            canvas.save();
            if (parent.getClipToPadding()) {
                i4 = parent.getPaddingLeft() + 0;
                width = (parent.getWidth() - parent.getPaddingRight()) + 0;
            } else {
                width = parent.getWidth() + 0;
                i4 = 0;
            }
            int childCount2 = parent.getChildCount();
            while (i5 < childCount2) {
                int i12 = i5 + 1;
                View childAt2 = parent.getChildAt(i5);
                int childAdapterPosition2 = parent.getChildAdapterPosition(childAt2);
                RecyclerView.LayoutManager layoutManager3 = parent.getLayoutManager();
                if (layoutManager3 == null) {
                    return;
                }
                C3236a m3947a2 = C3236a.m3947a(childAdapterPosition2, layoutManager3, m3945b);
                if (this.f8939b != dividerOrientation) {
                    i5 = m3945b ? m3947a2.f8943b : m3947a2.f8945d ? i12 : 0;
                }
                Drawable drawable2 = this.f8941d;
                if (drawable2 != null) {
                    Rect rect = new Rect();
                    parent.getDecoratedBoundsWithMargins(childAt2, rect);
                    if (m3945b) {
                        i6 = -1;
                        if (drawable2.getIntrinsicHeight() != -1) {
                            drawable2.getIntrinsicHeight();
                        }
                    } else {
                        i6 = -1;
                        if (drawable2.getIntrinsicHeight() != -1) {
                            drawable2.getIntrinsicHeight();
                        }
                    }
                    if (m3945b) {
                        intrinsicHeight = rect.top;
                        i7 = (drawable2.getIntrinsicHeight() == i6 ? this.f8940c : drawable2.getIntrinsicHeight()) + intrinsicHeight;
                    } else {
                        i7 = rect.bottom;
                        intrinsicHeight = i7 - (drawable2.getIntrinsicHeight() == i6 ? this.f8940c : drawable2.getIntrinsicHeight());
                    }
                    drawable2.setBounds(i4, intrinsicHeight, width, i7);
                    drawable2.draw(canvas);
                }
            }
            canvas.restore();
            return;
        }
        if (ordinal != 2) {
            return;
        }
        canvas.save();
        int childCount3 = parent.getChildCount();
        int i13 = 0;
        while (i13 < childCount3) {
            int i14 = i13 + 1;
            View childAt3 = parent.getChildAt(i13);
            int childAdapterPosition3 = parent.getChildAdapterPosition(childAt3);
            if (childAdapterPosition3 == i10) {
                parent.invalidateItemDecorations();
            } else {
                RecyclerView.LayoutManager layoutManager4 = parent.getLayoutManager();
                if (layoutManager4 == null) {
                    return;
                }
                C3236a m3947a3 = C3236a.m3947a(childAdapterPosition3, layoutManager4, m3945b);
                Drawable drawable3 = this.f8941d;
                int intrinsicHeight2 = drawable3 == null ? this.f8940c : drawable3.getIntrinsicHeight() != i10 ? drawable3.getIntrinsicHeight() : drawable3.getIntrinsicWidth() != i10 ? drawable3.getIntrinsicWidth() : this.f8940c;
                int intrinsicWidth = drawable3 == null ? this.f8940c : drawable3.getIntrinsicWidth() != i10 ? drawable3.getIntrinsicWidth() : drawable3.getIntrinsicHeight() != i10 ? drawable3.getIntrinsicHeight() : this.f8940c;
                if (drawable3 != null) {
                    ViewGroup.LayoutParams layoutParams = childAt3.getLayoutParams();
                    Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView.LayoutParams");
                    RecyclerView.LayoutParams layoutParams2 = (RecyclerView.LayoutParams) layoutParams;
                    i8 = childCount3;
                    Rect rect2 = new Rect(childAt3.getLeft() + ((ViewGroup.MarginLayoutParams) layoutParams2).leftMargin, childAt3.getTop() + ((ViewGroup.MarginLayoutParams) layoutParams2).topMargin, childAt3.getRight() + ((ViewGroup.MarginLayoutParams) layoutParams2).rightMargin, childAt3.getBottom() + ((ViewGroup.MarginLayoutParams) layoutParams2).bottomMargin);
                    boolean z = m3947a3.f8943b;
                    if (z || !m3947a3.f8944c) {
                        i9 = 0;
                        if (!z && m3947a3.f8942a) {
                            int i15 = rect2.left + 0;
                            int i16 = rect2.top;
                            drawable3.setBounds(i15, i16 - intrinsicHeight2, (rect2.right + intrinsicWidth) - 0, i16);
                            drawable3.draw(canvas);
                        } else if (!z) {
                            int i17 = (rect2.left - intrinsicWidth) + 0;
                            int i18 = rect2.top;
                            drawable3.setBounds(i17, i18 - intrinsicHeight2, (rect2.right + intrinsicWidth) - 0, i18);
                            drawable3.draw(canvas);
                        }
                    } else {
                        i9 = 0;
                        int i19 = (rect2.left - intrinsicWidth) + 0;
                        int i20 = rect2.top;
                        drawable3.setBounds(i19, i20 - intrinsicHeight2, rect2.right - 0, i20);
                        drawable3.draw(canvas);
                    }
                    boolean z2 = m3947a3.f8945d;
                    if (!z2 && m3947a3.f8944c) {
                        int i21 = (rect2.left - intrinsicWidth) + i9;
                        int i22 = rect2.bottom;
                        drawable3.setBounds(i21, i22, rect2.right - i9, i22 + intrinsicHeight2);
                        drawable3.draw(canvas);
                    } else if (!z2 && m3947a3.f8942a) {
                        int i23 = rect2.left + i9;
                        int i24 = rect2.bottom;
                        drawable3.setBounds(i23, i24, (rect2.right + intrinsicWidth) - i9, i24 + intrinsicHeight2);
                        drawable3.draw(canvas);
                    } else if (!z2) {
                        int i25 = (rect2.left - intrinsicWidth) + i9;
                        int i26 = rect2.bottom;
                        drawable3.setBounds(i25, i26, (rect2.right + intrinsicWidth) - i9, i26 + intrinsicHeight2);
                        drawable3.draw(canvas);
                    }
                    boolean z3 = m3947a3.f8942a;
                    if (!z3 && m3947a3.f8943b) {
                        int i27 = rect2.left;
                        drawable3.setBounds(i27 - intrinsicWidth, rect2.top + 0, i27, rect2.bottom + intrinsicHeight2 + 0);
                        drawable3.draw(canvas);
                    } else if (!z3 && m3947a3.f8945d) {
                        int i28 = rect2.left;
                        drawable3.setBounds(i28 - intrinsicWidth, (rect2.top - intrinsicHeight2) + 0, i28, rect2.bottom - 0);
                        drawable3.draw(canvas);
                    } else if (!z3) {
                        int i29 = rect2.left;
                        drawable3.setBounds(i29 - intrinsicWidth, rect2.top + 0, i29, (rect2.bottom + intrinsicHeight2) - 0);
                        drawable3.draw(canvas);
                    }
                    boolean z4 = m3947a3.f8944c;
                    if (!z4 && m3947a3.f8943b) {
                        int i30 = rect2.right;
                        drawable3.setBounds(i30, rect2.top + 0, intrinsicWidth + i30, (rect2.bottom + intrinsicHeight2) - 0);
                        drawable3.draw(canvas);
                    } else if (!z4 && m3947a3.f8945d) {
                        int i31 = rect2.right;
                        drawable3.setBounds(i31, (rect2.top - intrinsicHeight2) + 0, intrinsicWidth + i31, rect2.bottom + 0);
                        drawable3.draw(canvas);
                    } else if (!z4) {
                        int i32 = rect2.right;
                        drawable3.setBounds(i32, rect2.top + 0, intrinsicWidth + i32, rect2.bottom + intrinsicHeight2 + 0);
                        drawable3.draw(canvas);
                    }
                    i10 = -1;
                    childCount3 = i8;
                    i13 = i14;
                }
            }
            i8 = childCount3;
            i10 = -1;
            childCount3 = i8;
            i13 = i14;
        }
        canvas.restore();
    }
}
