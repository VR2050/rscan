package com.angcyo.tablayout;

import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000d\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010!\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010 \n\u0002\b\u0004\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u001e\u0010&\u001a\u00020'2\u0006\u0010(\u001a\u00020\f2\u0006\u0010)\u001a\u00020'2\u0006\u0010*\u001a\u00020'J)\u0010+\u001a\u00020\u00002\u0006\u0010,\u001a\u00020\u00182\u0019\b\u0002\u0010-\u001a\u0013\u0012\u0004\u0012\u00020\u0012\u0012\u0004\u0012\u00020/0.¢\u0006\u0002\b0J\u001e\u00101\u001a\u00020'2\u0006\u0010(\u001a\u00020\f2\u0006\u0010)\u001a\u00020'2\u0006\u0010*\u001a\u00020'J\u001e\u00102\u001a\u00020/2\u0006\u00103\u001a\u00020\f2\u0006\u00104\u001a\u00020'2\u0006\u0010*\u001a\u00020'J6\u00105\u001a\u00020/2\u0006\u0010(\u001a\u00020\f2\b\b\u0002\u0010)\u001a\u00020'2\b\b\u0002\u00106\u001a\u00020'2\b\b\u0002\u0010*\u001a\u00020'2\b\b\u0002\u00107\u001a\u00020'J2\u00105\u001a\u00020/2\f\u00108\u001a\b\u0012\u0004\u0012\u00020\f0\u001e2\b\b\u0002\u0010)\u001a\u00020'2\b\b\u0002\u00106\u001a\u00020'2\b\b\u0002\u0010*\u001a\u00020'J$\u00109\u001a\u00020/2\b\b\u0002\u0010)\u001a\u00020'2\b\b\u0002\u00106\u001a\u00020'2\b\b\u0002\u0010*\u001a\u00020'J\u0006\u0010:\u001a\u00020/J\u0006\u0010;\u001a\u00020/J\f\u0010<\u001a\b\u0012\u0004\u0012\u00020\"0=J\n\u0010>\u001a\u00020'*\u00020\"J\u0012\u0010?\u001a\u00020/*\u00020\"2\u0006\u0010@\u001a\u00020'R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006R\u0011\u0010\u0007\u001a\u00020\b¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\nR\u001a\u0010\u000b\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\r\u0010\u000e\"\u0004\b\u000f\u0010\u0010R\u001a\u0010\u0011\u001a\u00020\u0012X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0013\u0010\u0014\"\u0004\b\u0015\u0010\u0016R\u001c\u0010\u0017\u001a\u0004\u0018\u00010\u0018X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0019\u0010\u001a\"\u0004\b\u001b\u0010\u001cR\u0019\u0010\u001d\u001a\b\u0012\u0004\u0012\u00020\f0\u001e8F¢\u0006\b\n\u0000\u001a\u0004\b\u001f\u0010 R\u0019\u0010!\u001a\b\u0012\u0004\u0012\u00020\"0\u001e8F¢\u0006\b\n\u0000\u001a\u0004\b#\u0010 R\u0017\u0010$\u001a\b\u0012\u0004\u0012\u00020\"0\u001e¢\u0006\b\n\u0000\u001a\u0004\b%\u0010 ¨\u0006A"}, m5311d2 = {"Lcom/angcyo/tablayout/DslSelector;", "", "()V", "_onCheckedChangeListener", "Landroid/widget/CompoundButton$OnCheckedChangeListener;", "get_onCheckedChangeListener", "()Landroid/widget/CompoundButton$OnCheckedChangeListener;", "_onChildClickListener", "Landroid/view/View$OnClickListener;", "get_onChildClickListener", "()Landroid/view/View$OnClickListener;", "dslSelectIndex", "", "getDslSelectIndex", "()I", "setDslSelectIndex", "(I)V", "dslSelectorConfig", "Lcom/angcyo/tablayout/DslSelectorConfig;", "getDslSelectorConfig", "()Lcom/angcyo/tablayout/DslSelectorConfig;", "setDslSelectorConfig", "(Lcom/angcyo/tablayout/DslSelectorConfig;)V", "parent", "Landroid/view/ViewGroup;", "getParent", "()Landroid/view/ViewGroup;", "setParent", "(Landroid/view/ViewGroup;)V", "selectorIndexList", "", "getSelectorIndexList", "()Ljava/util/List;", "selectorViewList", "Landroid/view/View;", "getSelectorViewList", "visibleViewList", "getVisibleViewList", "_selector", "", "index", "select", "fromUser", "install", "viewGroup", "config", "Lkotlin/Function1;", "", "Lkotlin/ExtensionFunctionType;", "interceptSelector", "notifySelectChange", "lastSelectorIndex", "reselect", "selector", "notify", "forceNotify", "indexList", "selectorAll", "updateClickListener", "updateStyle", "updateVisibleList", "", "isSe", "setSe", "se", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.h, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslSelector {

    /* renamed from: a */
    @Nullable
    public ViewGroup f1579a;

    /* renamed from: b */
    @NotNull
    public DslSelectorConfig f1580b = new DslSelectorConfig();

    /* renamed from: c */
    @NotNull
    public final List<View> f1581c = new ArrayList();

    /* renamed from: d */
    @NotNull
    public final List<Integer> f1582d = new ArrayList();

    /* renamed from: e */
    @NotNull
    public final List<View> f1583e = new ArrayList();

    /* renamed from: f */
    @NotNull
    public final View.OnClickListener f1584f = new View.OnClickListener() { // from class: b.e.a.b
        @Override // android.view.View.OnClickListener
        public final void onClick(View view) {
            DslSelector this$0 = DslSelector.this;
            Intrinsics.checkNotNullParameter(this$0, "this$0");
            int indexOf = this$0.f1581c.indexOf(view);
            Objects.requireNonNull(this$0.f1580b);
            Objects.requireNonNull(this$0.f1580b);
            List<View> list = this$0.f1581c;
            boolean z = false;
            boolean z2 = true;
            if (indexOf >= 0 && indexOf < list.size()) {
                z = true;
            }
            if (z) {
                Function4<? super View, ? super Integer, ? super Boolean, ? super Boolean, Boolean> function4 = this$0.f1580b.f1590d;
                View view2 = list.get(indexOf);
                Integer valueOf = Integer.valueOf(indexOf);
                Boolean bool = Boolean.TRUE;
                z2 = function4.invoke(view2, valueOf, bool, bool).booleanValue();
            }
            if (z2) {
                return;
            }
            int indexOf2 = this$0.f1581c.indexOf(view);
            if (view instanceof CompoundButton) {
                Objects.requireNonNull(this$0.f1580b);
            }
            this$0.m662d(indexOf2, true, true, true, false);
        }
    };

    /* renamed from: g */
    @NotNull
    public final CompoundButton.OnCheckedChangeListener f1585g = new CompoundButton.OnCheckedChangeListener() { // from class: b.e.a.a
        @Override // android.widget.CompoundButton.OnCheckedChangeListener
        public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
            compoundButton.setChecked(compoundButton.isSelected());
        }
    };

    /* renamed from: h */
    public int f1586h = -1;

    @NotNull
    /* renamed from: a */
    public final List<Integer> m659a() {
        this.f1582d.clear();
        int i2 = 0;
        for (Object obj : this.f1581c) {
            int i3 = i2 + 1;
            if (i2 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            if (m661c((View) obj)) {
                this.f1582d.add(Integer.valueOf(i2));
            }
            i2 = i3;
        }
        return this.f1582d;
    }

    @NotNull
    /* renamed from: b */
    public final List<View> m660b() {
        this.f1583e.clear();
        int i2 = 0;
        for (Object obj : this.f1581c) {
            int i3 = i2 + 1;
            if (i2 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            View view = (View) obj;
            if (m661c(view) || i2 == this.f1586h) {
                this.f1583e.add(view);
            }
            i2 = i3;
        }
        return this.f1583e;
    }

    /* renamed from: c */
    public final boolean m661c(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        if (!view.isSelected()) {
            if (!(view instanceof CompoundButton ? ((CompoundButton) view).isChecked() : false)) {
                return false;
            }
        }
        return true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:75:0x0084, code lost:
    
        if (r9.contains(java.lang.Integer.valueOf(r17)) != false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0090, code lost:
    
        if (r9.contains(java.lang.Integer.valueOf(r17)) == false) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x00a2, code lost:
    
        if (r9 > Integer.MAX_VALUE) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x00b2, code lost:
    
        r9 = r8.get(r17);
        m663f(r9, r18);
        java.util.Objects.requireNonNull(r16.f1580b);
        r10 = r10.iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x00c8, code lost:
    
        if (r10.hasNext() == false) goto L103;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x00ca, code lost:
    
        r11 = (android.view.View) r10.next();
        r12 = r8.indexOf(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x00d4, code lost:
    
        if (r12 == r17) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x00d6, code lost:
    
        r13 = r16.f1580b.f1590d;
        r14 = java.lang.Integer.valueOf(r12);
        r15 = java.lang.Boolean.FALSE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x00ee, code lost:
    
        if (r13.invoke(r11, r14, r15, java.lang.Boolean.valueOf(r20)).booleanValue() != false) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x00f0, code lost:
    
        m663f(r11, false);
        r16.f1580b.f1587a.invoke(r11, java.lang.Integer.valueOf(r12), r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x0100, code lost:
    
        r16.f1580b.f1587a.invoke(r9, java.lang.Integer.valueOf(r17), java.lang.Boolean.valueOf(r18));
        r6 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x00af, code lost:
    
        if (r9 < 1) goto L16;
     */
    /* JADX WARN: Removed duplicated region for block: B:19:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0126  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0161 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0170  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x017a  */
    /* JADX WARN: Removed duplicated region for block: B:39:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0172  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0130  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0128  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0120  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m662d(int r17, boolean r18, boolean r19, boolean r20, boolean r21) {
        /*
            Method dump skipped, instructions count: 434
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.angcyo.tablayout.DslSelector.m662d(int, boolean, boolean, boolean, boolean):void");
    }

    /* renamed from: f */
    public final void m663f(@NotNull View view, boolean z) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setSelected(z);
        if (view instanceof CompoundButton) {
            ((CompoundButton) view).setChecked(z);
        }
    }

    /* renamed from: g */
    public final void m664g() {
        ViewGroup viewGroup = this.f1579a;
        if (viewGroup == null) {
            return;
        }
        int i2 = 0;
        int childCount = viewGroup.getChildCount();
        while (i2 < childCount) {
            int i3 = i2 + 1;
            View childAt = viewGroup.getChildAt(i2);
            if (childAt != null) {
                childAt.setOnClickListener(this.f1584f);
                if (childAt instanceof CompoundButton) {
                    ((CompoundButton) childAt).setOnCheckedChangeListener(this.f1585g);
                }
            }
            i2 = i3;
        }
    }

    /* renamed from: h */
    public final void m665h() {
        int i2 = 0;
        for (Object obj : this.f1581c) {
            int i3 = i2 + 1;
            if (i2 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            View view = (View) obj;
            this.f1580b.f1587a.invoke(view, Integer.valueOf(i2), Boolean.valueOf(this.f1586h == i2 || m661c(view)));
            i2 = i3;
        }
    }

    @NotNull
    /* renamed from: i */
    public final List<View> m666i() {
        this.f1581c.clear();
        ViewGroup viewGroup = this.f1579a;
        boolean z = false;
        if (viewGroup != null) {
            int childCount = viewGroup.getChildCount();
            int i2 = 0;
            while (i2 < childCount) {
                int i3 = i2 + 1;
                View childAt = viewGroup.getChildAt(i2);
                if (childAt != null && childAt.getVisibility() == 0) {
                    this.f1581c.add(childAt);
                }
                i2 = i3;
            }
        }
        int size = this.f1581c.size();
        int i4 = this.f1586h;
        if (i4 >= 0 && i4 < size) {
            z = true;
        }
        if (!z) {
            this.f1586h = -1;
        } else if (!m661c(this.f1581c.get(i4))) {
            m663f(this.f1581c.get(this.f1586h), true);
        }
        return this.f1581c;
    }
}
