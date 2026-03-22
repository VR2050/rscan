package com.google.android.flexbox;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseIntArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.Nullable;
import androidx.core.view.ViewCompat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p254b.C2411b;
import p005b.p199l.p200a.p254b.C2412c;
import p005b.p199l.p200a.p254b.InterfaceC2410a;

/* loaded from: classes.dex */
public class FlexboxLayout extends ViewGroup implements InterfaceC2410a {

    /* renamed from: c */
    public int f9759c;

    /* renamed from: e */
    public int f9760e;

    /* renamed from: f */
    public int f9761f;

    /* renamed from: g */
    public int f9762g;

    /* renamed from: h */
    public int f9763h;

    /* renamed from: i */
    public int f9764i;

    /* renamed from: j */
    @Nullable
    public Drawable f9765j;

    /* renamed from: k */
    @Nullable
    public Drawable f9766k;

    /* renamed from: l */
    public int f9767l;

    /* renamed from: m */
    public int f9768m;

    /* renamed from: n */
    public int f9769n;

    /* renamed from: o */
    public int f9770o;

    /* renamed from: p */
    public int[] f9771p;

    /* renamed from: q */
    public SparseIntArray f9772q;

    /* renamed from: r */
    public C2412c f9773r;

    /* renamed from: s */
    public List<C2411b> f9774s;

    /* renamed from: t */
    public C2412c.b f9775t;

    public FlexboxLayout(Context context) {
        this(context, null);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: a */
    public void mo2710a(View view, int i2, int i3, C2411b c2411b) {
        if (m4154p(i2, i3)) {
            if (mo2718i()) {
                int i4 = c2411b.f6422e;
                int i5 = this.f9770o;
                c2411b.f6422e = i4 + i5;
                c2411b.f6423f += i5;
                return;
            }
            int i6 = c2411b.f6422e;
            int i7 = this.f9769n;
            c2411b.f6422e = i6 + i7;
            c2411b.f6423f += i7;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // android.view.ViewGroup
    public void addView(View view, int i2, ViewGroup.LayoutParams layoutParams) {
        if (this.f9772q == null) {
            this.f9772q = new SparseIntArray(getChildCount());
        }
        C2412c c2412c = this.f9773r;
        SparseIntArray sparseIntArray = this.f9772q;
        int flexItemCount = c2412c.f6436a.getFlexItemCount();
        List<C2412c.c> m2729f = c2412c.m2729f(flexItemCount);
        C2412c.c cVar = new C2412c.c(null);
        if (view == null || !(layoutParams instanceof FlexItem)) {
            cVar.f6444e = 1;
        } else {
            cVar.f6444e = ((FlexItem) layoutParams).getOrder();
        }
        if (i2 == -1 || i2 == flexItemCount) {
            cVar.f6443c = flexItemCount;
        } else if (i2 < c2412c.f6436a.getFlexItemCount()) {
            cVar.f6443c = i2;
            for (int i3 = i2; i3 < flexItemCount; i3++) {
                ((C2412c.c) ((ArrayList) m2729f).get(i3)).f6443c++;
            }
        } else {
            cVar.f6443c = flexItemCount;
        }
        ((ArrayList) m2729f).add(cVar);
        this.f9771p = c2412c.m2747x(flexItemCount + 1, m2729f, sparseIntArray);
        super.addView(view, i2, layoutParams);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: b */
    public void mo2711b(C2411b c2411b) {
        if (mo2718i()) {
            if ((this.f9768m & 4) > 0) {
                int i2 = c2411b.f6422e;
                int i3 = this.f9770o;
                c2411b.f6422e = i2 + i3;
                c2411b.f6423f += i3;
                return;
            }
            return;
        }
        if ((this.f9767l & 4) > 0) {
            int i4 = c2411b.f6422e;
            int i5 = this.f9769n;
            c2411b.f6422e = i4 + i5;
            c2411b.f6423f += i5;
        }
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: c */
    public View mo2712c(int i2) {
        return m4153o(i2);
    }

    @Override // android.view.ViewGroup
    public boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof LayoutParams;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: d */
    public int mo2713d(int i2, int i3, int i4) {
        return ViewGroup.getChildMeasureSpec(i2, i3, i4);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: e */
    public void mo2714e(int i2, View view) {
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: f */
    public View mo2715f(int i2) {
        return getChildAt(i2);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: g */
    public int mo2716g(View view, int i2, int i3) {
        int i4;
        int i5;
        if (mo2718i()) {
            i4 = m4154p(i2, i3) ? 0 + this.f9770o : 0;
            if ((this.f9768m & 4) <= 0) {
                return i4;
            }
            i5 = this.f9770o;
        } else {
            i4 = m4154p(i2, i3) ? 0 + this.f9769n : 0;
            if ((this.f9767l & 4) <= 0) {
                return i4;
            }
            i5 = this.f9769n;
        }
        return i4 + i5;
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new LayoutParams(getContext(), attributeSet);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getAlignContent() {
        return this.f9763h;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getAlignItems() {
        return this.f9762g;
    }

    @Nullable
    public Drawable getDividerDrawableHorizontal() {
        return this.f9765j;
    }

    @Nullable
    public Drawable getDividerDrawableVertical() {
        return this.f9766k;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getFlexDirection() {
        return this.f9759c;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getFlexItemCount() {
        return getChildCount();
    }

    public List<C2411b> getFlexLines() {
        ArrayList arrayList = new ArrayList(this.f9774s.size());
        for (C2411b c2411b : this.f9774s) {
            if (c2411b.m2720a() != 0) {
                arrayList.add(c2411b);
            }
        }
        return arrayList;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public List<C2411b> getFlexLinesInternal() {
        return this.f9774s;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getFlexWrap() {
        return this.f9760e;
    }

    public int getJustifyContent() {
        return this.f9761f;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getLargestMainSize() {
        Iterator<C2411b> it = this.f9774s.iterator();
        int i2 = Integer.MIN_VALUE;
        while (it.hasNext()) {
            i2 = Math.max(i2, it.next().f6422e);
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getMaxLine() {
        return this.f9764i;
    }

    public int getShowDividerHorizontal() {
        return this.f9767l;
    }

    public int getShowDividerVertical() {
        return this.f9768m;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public int getSumOfCrossSize() {
        int size = this.f9774s.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            C2411b c2411b = this.f9774s.get(i3);
            if (m4155q(i3)) {
                i2 += mo2718i() ? this.f9769n : this.f9770o;
            }
            if (m4156r(i3)) {
                i2 += mo2718i() ? this.f9769n : this.f9770o;
            }
            i2 += c2411b.f6424g;
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: h */
    public int mo2717h(int i2, int i3, int i4) {
        return ViewGroup.getChildMeasureSpec(i2, i3, i4);
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: i */
    public boolean mo2718i() {
        int i2 = this.f9759c;
        return i2 == 0 || i2 == 1;
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    /* renamed from: j */
    public int mo2719j(View view) {
        return 0;
    }

    /* renamed from: k */
    public final void m4149k(Canvas canvas, boolean z, boolean z2) {
        int paddingLeft = getPaddingLeft();
        int max = Math.max(0, (getWidth() - getPaddingRight()) - paddingLeft);
        int size = this.f9774s.size();
        for (int i2 = 0; i2 < size; i2++) {
            C2411b c2411b = this.f9774s.get(i2);
            for (int i3 = 0; i3 < c2411b.f6425h; i3++) {
                int i4 = c2411b.f6432o + i3;
                View m4153o = m4153o(i4);
                if (m4153o != null && m4153o.getVisibility() != 8) {
                    LayoutParams layoutParams = (LayoutParams) m4153o.getLayoutParams();
                    if (m4154p(i4, i3)) {
                        m4152n(canvas, z ? m4153o.getRight() + ((ViewGroup.MarginLayoutParams) layoutParams).rightMargin : (m4153o.getLeft() - ((ViewGroup.MarginLayoutParams) layoutParams).leftMargin) - this.f9770o, c2411b.f6419b, c2411b.f6424g);
                    }
                    if (i3 == c2411b.f6425h - 1 && (this.f9768m & 4) > 0) {
                        m4152n(canvas, z ? (m4153o.getLeft() - ((ViewGroup.MarginLayoutParams) layoutParams).leftMargin) - this.f9770o : m4153o.getRight() + ((ViewGroup.MarginLayoutParams) layoutParams).rightMargin, c2411b.f6419b, c2411b.f6424g);
                    }
                }
            }
            if (m4155q(i2)) {
                m4151m(canvas, paddingLeft, z2 ? c2411b.f6421d : c2411b.f6419b - this.f9769n, max);
            }
            if (m4156r(i2) && (this.f9767l & 4) > 0) {
                m4151m(canvas, paddingLeft, z2 ? c2411b.f6419b - this.f9769n : c2411b.f6421d, max);
            }
        }
    }

    /* renamed from: l */
    public final void m4150l(Canvas canvas, boolean z, boolean z2) {
        int paddingTop = getPaddingTop();
        int max = Math.max(0, (getHeight() - getPaddingBottom()) - paddingTop);
        int size = this.f9774s.size();
        for (int i2 = 0; i2 < size; i2++) {
            C2411b c2411b = this.f9774s.get(i2);
            for (int i3 = 0; i3 < c2411b.f6425h; i3++) {
                int i4 = c2411b.f6432o + i3;
                View m4153o = m4153o(i4);
                if (m4153o != null && m4153o.getVisibility() != 8) {
                    LayoutParams layoutParams = (LayoutParams) m4153o.getLayoutParams();
                    if (m4154p(i4, i3)) {
                        m4151m(canvas, c2411b.f6418a, z2 ? m4153o.getBottom() + ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin : (m4153o.getTop() - ((ViewGroup.MarginLayoutParams) layoutParams).topMargin) - this.f9769n, c2411b.f6424g);
                    }
                    if (i3 == c2411b.f6425h - 1 && (this.f9767l & 4) > 0) {
                        m4151m(canvas, c2411b.f6418a, z2 ? (m4153o.getTop() - ((ViewGroup.MarginLayoutParams) layoutParams).topMargin) - this.f9769n : m4153o.getBottom() + ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin, c2411b.f6424g);
                    }
                }
            }
            if (m4155q(i2)) {
                m4152n(canvas, z ? c2411b.f6420c : c2411b.f6418a - this.f9770o, paddingTop, max);
            }
            if (m4156r(i2) && (this.f9768m & 4) > 0) {
                m4152n(canvas, z ? c2411b.f6418a - this.f9770o : c2411b.f6420c, paddingTop, max);
            }
        }
    }

    /* renamed from: m */
    public final void m4151m(Canvas canvas, int i2, int i3, int i4) {
        Drawable drawable = this.f9765j;
        if (drawable == null) {
            return;
        }
        drawable.setBounds(i2, i3, i4 + i2, this.f9769n + i3);
        this.f9765j.draw(canvas);
    }

    /* renamed from: n */
    public final void m4152n(Canvas canvas, int i2, int i3, int i4) {
        Drawable drawable = this.f9766k;
        if (drawable == null) {
            return;
        }
        drawable.setBounds(i2, i3, this.f9770o + i2, i4 + i3);
        this.f9766k.draw(canvas);
    }

    /* renamed from: o */
    public View m4153o(int i2) {
        if (i2 < 0) {
            return null;
        }
        int[] iArr = this.f9771p;
        if (i2 >= iArr.length) {
            return null;
        }
        return getChildAt(iArr[i2]);
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        if (this.f9766k == null && this.f9765j == null) {
            return;
        }
        if (this.f9767l == 0 && this.f9768m == 0) {
            return;
        }
        int layoutDirection = ViewCompat.getLayoutDirection(this);
        int i2 = this.f9759c;
        if (i2 == 0) {
            m4149k(canvas, layoutDirection == 1, this.f9760e == 2);
            return;
        }
        if (i2 == 1) {
            m4149k(canvas, layoutDirection != 1, this.f9760e == 2);
            return;
        }
        if (i2 == 2) {
            boolean z = layoutDirection == 1;
            if (this.f9760e == 2) {
                z = !z;
            }
            m4150l(canvas, z, false);
            return;
        }
        if (i2 != 3) {
            return;
        }
        boolean z2 = layoutDirection == 1;
        if (this.f9760e == 2) {
            z2 = !z2;
        }
        m4150l(canvas, z2, true);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        boolean z2;
        int layoutDirection = ViewCompat.getLayoutDirection(this);
        int i6 = this.f9759c;
        if (i6 == 0) {
            m4157s(layoutDirection == 1, i2, i3, i4, i5);
            return;
        }
        if (i6 == 1) {
            m4157s(layoutDirection != 1, i2, i3, i4, i5);
            return;
        }
        if (i6 == 2) {
            z2 = layoutDirection == 1;
            if (this.f9760e == 2) {
                z2 = !z2;
            }
            m4158t(z2, false, i2, i3, i4, i5);
            return;
        }
        if (i6 != 3) {
            StringBuilder m586H = C1499a.m586H("Invalid flex direction is set: ");
            m586H.append(this.f9759c);
            throw new IllegalStateException(m586H.toString());
        }
        z2 = layoutDirection == 1;
        if (this.f9760e == 2) {
            z2 = !z2;
        }
        m4158t(z2, true, i2, i3, i4, i5);
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00ec  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onMeasure(int r15, int r16) {
        /*
            Method dump skipped, instructions count: 380
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.flexbox.FlexboxLayout.onMeasure(int, int):void");
    }

    /* renamed from: p */
    public final boolean m4154p(int i2, int i3) {
        boolean z;
        int i4 = 1;
        while (true) {
            if (i4 > i3) {
                z = true;
                break;
            }
            View m4153o = m4153o(i2 - i4);
            if (m4153o != null && m4153o.getVisibility() != 8) {
                z = false;
                break;
            }
            i4++;
        }
        return z ? mo2718i() ? (this.f9768m & 1) != 0 : (this.f9767l & 1) != 0 : mo2718i() ? (this.f9768m & 2) != 0 : (this.f9767l & 2) != 0;
    }

    /* renamed from: q */
    public final boolean m4155q(int i2) {
        boolean z;
        if (i2 < 0 || i2 >= this.f9774s.size()) {
            return false;
        }
        int i3 = 0;
        while (true) {
            if (i3 >= i2) {
                z = true;
                break;
            }
            if (this.f9774s.get(i3).m2720a() > 0) {
                z = false;
                break;
            }
            i3++;
        }
        return z ? mo2718i() ? (this.f9767l & 1) != 0 : (this.f9768m & 1) != 0 : mo2718i() ? (this.f9767l & 2) != 0 : (this.f9768m & 2) != 0;
    }

    /* renamed from: r */
    public final boolean m4156r(int i2) {
        if (i2 < 0 || i2 >= this.f9774s.size()) {
            return false;
        }
        for (int i3 = i2 + 1; i3 < this.f9774s.size(); i3++) {
            if (this.f9774s.get(i3).m2720a() > 0) {
                return false;
            }
        }
        return mo2718i() ? (this.f9767l & 4) != 0 : (this.f9768m & 4) != 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x00d9  */
    /* renamed from: s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m4157s(boolean r26, int r27, int r28, int r29, int r30) {
        /*
            Method dump skipped, instructions count: 522
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.flexbox.FlexboxLayout.m4157s(boolean, int, int, int, int):void");
    }

    public void setAlignContent(int i2) {
        if (this.f9763h != i2) {
            this.f9763h = i2;
            requestLayout();
        }
    }

    public void setAlignItems(int i2) {
        if (this.f9762g != i2) {
            this.f9762g = i2;
            requestLayout();
        }
    }

    public void setDividerDrawable(Drawable drawable) {
        setDividerDrawableHorizontal(drawable);
        setDividerDrawableVertical(drawable);
    }

    public void setDividerDrawableHorizontal(@Nullable Drawable drawable) {
        if (drawable == this.f9765j) {
            return;
        }
        this.f9765j = drawable;
        if (drawable != null) {
            this.f9769n = drawable.getIntrinsicHeight();
        } else {
            this.f9769n = 0;
        }
        if (this.f9765j == null && this.f9766k == null) {
            setWillNotDraw(true);
        } else {
            setWillNotDraw(false);
        }
        requestLayout();
    }

    public void setDividerDrawableVertical(@Nullable Drawable drawable) {
        if (drawable == this.f9766k) {
            return;
        }
        this.f9766k = drawable;
        if (drawable != null) {
            this.f9770o = drawable.getIntrinsicWidth();
        } else {
            this.f9770o = 0;
        }
        if (this.f9765j == null && this.f9766k == null) {
            setWillNotDraw(true);
        } else {
            setWillNotDraw(false);
        }
        requestLayout();
    }

    public void setFlexDirection(int i2) {
        if (this.f9759c != i2) {
            this.f9759c = i2;
            requestLayout();
        }
    }

    @Override // p005b.p199l.p200a.p254b.InterfaceC2410a
    public void setFlexLines(List<C2411b> list) {
        this.f9774s = list;
    }

    public void setFlexWrap(int i2) {
        if (this.f9760e != i2) {
            this.f9760e = i2;
            requestLayout();
        }
    }

    public void setJustifyContent(int i2) {
        if (this.f9761f != i2) {
            this.f9761f = i2;
            requestLayout();
        }
    }

    public void setMaxLine(int i2) {
        if (this.f9764i != i2) {
            this.f9764i = i2;
            requestLayout();
        }
    }

    public void setShowDivider(int i2) {
        setShowDividerVertical(i2);
        setShowDividerHorizontal(i2);
    }

    public void setShowDividerHorizontal(int i2) {
        if (i2 != this.f9767l) {
            this.f9767l = i2;
            requestLayout();
        }
    }

    public void setShowDividerVertical(int i2) {
        if (i2 != this.f9768m) {
            this.f9768m = i2;
            requestLayout();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x00d7  */
    /* renamed from: t */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m4158t(boolean r28, boolean r29, int r30, int r31, int r32, int r33) {
        /*
            Method dump skipped, instructions count: 514
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.flexbox.FlexboxLayout.m4158t(boolean, boolean, int, int, int, int):void");
    }

    /* renamed from: u */
    public final void m4159u(int i2, int i3, int i4, int i5) {
        int paddingBottom;
        int largestMainSize;
        int resolveSizeAndState;
        int resolveSizeAndState2;
        int mode = View.MeasureSpec.getMode(i3);
        int size = View.MeasureSpec.getSize(i3);
        int mode2 = View.MeasureSpec.getMode(i4);
        int size2 = View.MeasureSpec.getSize(i4);
        if (i2 == 0 || i2 == 1) {
            paddingBottom = getPaddingBottom() + getPaddingTop() + getSumOfCrossSize();
            largestMainSize = getLargestMainSize();
        } else {
            if (i2 != 2 && i2 != 3) {
                throw new IllegalArgumentException(C1499a.m626l("Invalid flex direction: ", i2));
            }
            paddingBottom = getLargestMainSize();
            largestMainSize = getPaddingRight() + getPaddingLeft() + getSumOfCrossSize();
        }
        if (mode == Integer.MIN_VALUE) {
            if (size < largestMainSize) {
                i5 = View.combineMeasuredStates(i5, 16777216);
            } else {
                size = largestMainSize;
            }
            resolveSizeAndState = View.resolveSizeAndState(size, i3, i5);
        } else if (mode == 0) {
            resolveSizeAndState = View.resolveSizeAndState(largestMainSize, i3, i5);
        } else {
            if (mode != 1073741824) {
                throw new IllegalStateException(C1499a.m626l("Unknown width mode is set: ", mode));
            }
            if (size < largestMainSize) {
                i5 = View.combineMeasuredStates(i5, 16777216);
            }
            resolveSizeAndState = View.resolveSizeAndState(size, i3, i5);
        }
        if (mode2 == Integer.MIN_VALUE) {
            if (size2 < paddingBottom) {
                i5 = View.combineMeasuredStates(i5, 256);
            } else {
                size2 = paddingBottom;
            }
            resolveSizeAndState2 = View.resolveSizeAndState(size2, i4, i5);
        } else if (mode2 == 0) {
            resolveSizeAndState2 = View.resolveSizeAndState(paddingBottom, i4, i5);
        } else {
            if (mode2 != 1073741824) {
                throw new IllegalStateException(C1499a.m626l("Unknown height mode is set: ", mode2));
            }
            if (size2 < paddingBottom) {
                i5 = View.combineMeasuredStates(i5, 256);
            }
            resolveSizeAndState2 = View.resolveSizeAndState(size2, i4, i5);
        }
        setMeasuredDimension(resolveSizeAndState, resolveSizeAndState2);
    }

    public FlexboxLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof LayoutParams ? new LayoutParams((LayoutParams) layoutParams) : layoutParams instanceof ViewGroup.MarginLayoutParams ? new LayoutParams((ViewGroup.MarginLayoutParams) layoutParams) : new LayoutParams(layoutParams);
    }

    public FlexboxLayout(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f9764i = -1;
        this.f9773r = new C2412c(this);
        this.f9774s = new ArrayList();
        this.f9775t = new C2412c.b();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.FlexboxLayout, i2, 0);
        this.f9759c = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_flexDirection, 0);
        this.f9760e = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_flexWrap, 0);
        this.f9761f = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_justifyContent, 0);
        this.f9762g = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_alignItems, 0);
        this.f9763h = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_alignContent, 0);
        this.f9764i = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_maxLine, -1);
        Drawable drawable = obtainStyledAttributes.getDrawable(R$styleable.FlexboxLayout_dividerDrawable);
        if (drawable != null) {
            setDividerDrawableHorizontal(drawable);
            setDividerDrawableVertical(drawable);
        }
        Drawable drawable2 = obtainStyledAttributes.getDrawable(R$styleable.FlexboxLayout_dividerDrawableHorizontal);
        if (drawable2 != null) {
            setDividerDrawableHorizontal(drawable2);
        }
        Drawable drawable3 = obtainStyledAttributes.getDrawable(R$styleable.FlexboxLayout_dividerDrawableVertical);
        if (drawable3 != null) {
            setDividerDrawableVertical(drawable3);
        }
        int i3 = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_showDivider, 0);
        if (i3 != 0) {
            this.f9768m = i3;
            this.f9767l = i3;
        }
        int i4 = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_showDividerVertical, 0);
        if (i4 != 0) {
            this.f9768m = i4;
        }
        int i5 = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_showDividerHorizontal, 0);
        if (i5 != 0) {
            this.f9767l = i5;
        }
        obtainStyledAttributes.recycle();
    }

    public static class LayoutParams extends ViewGroup.MarginLayoutParams implements FlexItem {
        public static final Parcelable.Creator<LayoutParams> CREATOR = new C3330a();

        /* renamed from: c */
        public int f9776c;

        /* renamed from: e */
        public float f9777e;

        /* renamed from: f */
        public float f9778f;

        /* renamed from: g */
        public int f9779g;

        /* renamed from: h */
        public float f9780h;

        /* renamed from: i */
        public int f9781i;

        /* renamed from: j */
        public int f9782j;

        /* renamed from: k */
        public int f9783k;

        /* renamed from: l */
        public int f9784l;

        /* renamed from: m */
        public boolean f9785m;

        /* renamed from: com.google.android.flexbox.FlexboxLayout$LayoutParams$a */
        public static class C3330a implements Parcelable.Creator<LayoutParams> {
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
            this.f9776c = 1;
            this.f9777e = 0.0f;
            this.f9778f = 1.0f;
            this.f9779g = -1;
            this.f9780h = -1.0f;
            this.f9781i = -1;
            this.f9782j = -1;
            this.f9783k = ViewCompat.MEASURED_SIZE_MASK;
            this.f9784l = ViewCompat.MEASURED_SIZE_MASK;
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.FlexboxLayout_Layout);
            this.f9776c = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_Layout_layout_order, 1);
            this.f9777e = obtainStyledAttributes.getFloat(R$styleable.FlexboxLayout_Layout_layout_flexGrow, 0.0f);
            this.f9778f = obtainStyledAttributes.getFloat(R$styleable.FlexboxLayout_Layout_layout_flexShrink, 1.0f);
            this.f9779g = obtainStyledAttributes.getInt(R$styleable.FlexboxLayout_Layout_layout_alignSelf, -1);
            this.f9780h = obtainStyledAttributes.getFraction(R$styleable.FlexboxLayout_Layout_layout_flexBasisPercent, 1, 1, -1.0f);
            this.f9781i = obtainStyledAttributes.getDimensionPixelSize(R$styleable.FlexboxLayout_Layout_layout_minWidth, -1);
            this.f9782j = obtainStyledAttributes.getDimensionPixelSize(R$styleable.FlexboxLayout_Layout_layout_minHeight, -1);
            this.f9783k = obtainStyledAttributes.getDimensionPixelSize(R$styleable.FlexboxLayout_Layout_layout_maxWidth, ViewCompat.MEASURED_SIZE_MASK);
            this.f9784l = obtainStyledAttributes.getDimensionPixelSize(R$styleable.FlexboxLayout_Layout_layout_maxHeight, ViewCompat.MEASURED_SIZE_MASK);
            this.f9785m = obtainStyledAttributes.getBoolean(R$styleable.FlexboxLayout_Layout_layout_wrapBefore, false);
            obtainStyledAttributes.recycle();
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: a */
        public int mo4134a() {
            return this.f9779g;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: c */
        public float mo4135c() {
            return this.f9778f;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: f */
        public int mo4136f() {
            return this.f9781i;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: g */
        public void mo4137g(int i2) {
            this.f9781i = i2;
        }

        @Override // com.google.android.flexbox.FlexItem
        public int getHeight() {
            return ((ViewGroup.MarginLayoutParams) this).height;
        }

        @Override // com.google.android.flexbox.FlexItem
        public int getOrder() {
            return this.f9776c;
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
            this.f9782j = i2;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: m */
        public float mo4142m() {
            return this.f9777e;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: n */
        public float mo4143n() {
            return this.f9780h;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: p */
        public int mo4144p() {
            return ((ViewGroup.MarginLayoutParams) this).rightMargin;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: r */
        public int mo4145r() {
            return this.f9782j;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: s */
        public boolean mo4146s() {
            return this.f9785m;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: t */
        public int mo4147t() {
            return this.f9784l;
        }

        @Override // com.google.android.flexbox.FlexItem
        /* renamed from: v */
        public int mo4148v() {
            return this.f9783k;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeInt(this.f9776c);
            parcel.writeFloat(this.f9777e);
            parcel.writeFloat(this.f9778f);
            parcel.writeInt(this.f9779g);
            parcel.writeFloat(this.f9780h);
            parcel.writeInt(this.f9781i);
            parcel.writeInt(this.f9782j);
            parcel.writeInt(this.f9783k);
            parcel.writeInt(this.f9784l);
            parcel.writeByte(this.f9785m ? (byte) 1 : (byte) 0);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).bottomMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).leftMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).rightMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).topMargin);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).height);
            parcel.writeInt(((ViewGroup.MarginLayoutParams) this).width);
        }

        public LayoutParams(LayoutParams layoutParams) {
            super((ViewGroup.MarginLayoutParams) layoutParams);
            this.f9776c = 1;
            this.f9777e = 0.0f;
            this.f9778f = 1.0f;
            this.f9779g = -1;
            this.f9780h = -1.0f;
            this.f9781i = -1;
            this.f9782j = -1;
            this.f9783k = ViewCompat.MEASURED_SIZE_MASK;
            this.f9784l = ViewCompat.MEASURED_SIZE_MASK;
            this.f9776c = layoutParams.f9776c;
            this.f9777e = layoutParams.f9777e;
            this.f9778f = layoutParams.f9778f;
            this.f9779g = layoutParams.f9779g;
            this.f9780h = layoutParams.f9780h;
            this.f9781i = layoutParams.f9781i;
            this.f9782j = layoutParams.f9782j;
            this.f9783k = layoutParams.f9783k;
            this.f9784l = layoutParams.f9784l;
            this.f9785m = layoutParams.f9785m;
        }

        public LayoutParams(ViewGroup.LayoutParams layoutParams) {
            super(layoutParams);
            this.f9776c = 1;
            this.f9777e = 0.0f;
            this.f9778f = 1.0f;
            this.f9779g = -1;
            this.f9780h = -1.0f;
            this.f9781i = -1;
            this.f9782j = -1;
            this.f9783k = ViewCompat.MEASURED_SIZE_MASK;
            this.f9784l = ViewCompat.MEASURED_SIZE_MASK;
        }

        public LayoutParams(ViewGroup.MarginLayoutParams marginLayoutParams) {
            super(marginLayoutParams);
            this.f9776c = 1;
            this.f9777e = 0.0f;
            this.f9778f = 1.0f;
            this.f9779g = -1;
            this.f9780h = -1.0f;
            this.f9781i = -1;
            this.f9782j = -1;
            this.f9783k = ViewCompat.MEASURED_SIZE_MASK;
            this.f9784l = ViewCompat.MEASURED_SIZE_MASK;
        }

        public LayoutParams(Parcel parcel) {
            super(0, 0);
            this.f9776c = 1;
            this.f9777e = 0.0f;
            this.f9778f = 1.0f;
            this.f9779g = -1;
            this.f9780h = -1.0f;
            this.f9781i = -1;
            this.f9782j = -1;
            this.f9783k = ViewCompat.MEASURED_SIZE_MASK;
            this.f9784l = ViewCompat.MEASURED_SIZE_MASK;
            this.f9776c = parcel.readInt();
            this.f9777e = parcel.readFloat();
            this.f9778f = parcel.readFloat();
            this.f9779g = parcel.readInt();
            this.f9780h = parcel.readFloat();
            this.f9781i = parcel.readInt();
            this.f9782j = parcel.readInt();
            this.f9783k = parcel.readInt();
            this.f9784l = parcel.readInt();
            this.f9785m = parcel.readByte() != 0;
            ((ViewGroup.MarginLayoutParams) this).bottomMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).leftMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).rightMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).topMargin = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).height = parcel.readInt();
            ((ViewGroup.MarginLayoutParams) this).width = parcel.readInt();
        }
    }
}
