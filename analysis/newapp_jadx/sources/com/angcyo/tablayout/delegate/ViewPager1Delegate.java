package com.angcyo.tablayout.delegate;

import androidx.viewpager.widget.ViewPager;
import com.angcyo.tablayout.DslTabLayout;
import com.angcyo.tablayout.ViewPagerDelegate;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u0007\n\u0002\b\t\b\u0016\u0018\u0000 !2\u00020\u00012\u00020\u0002:\u0001!B#\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\b\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u0012\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0002\u0010\tJ\b\u0010\u0011\u001a\u00020\u0012H\u0016J\u0010\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0012H\u0016J \u0010\u0016\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u00122\u0006\u0010\u0018\u001a\u00020\u00192\u0006\u0010\u001a\u001a\u00020\u0012H\u0016J\u0010\u0010\u001b\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0012H\u0016J(\u0010\u001c\u001a\u00020\u00142\u0006\u0010\u001d\u001a\u00020\u00122\u0006\u0010\u001e\u001a\u00020\u00122\u0006\u0010\u001f\u001a\u00020\b2\u0006\u0010 \u001a\u00020\bH\u0016R\u0013\u0010\u0005\u001a\u0004\u0018\u00010\u0006¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR\u0015\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\n\n\u0002\u0010\u000e\u001a\u0004\b\f\u0010\rR\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010¨\u0006\""}, m5311d2 = {"Lcom/angcyo/tablayout/delegate/ViewPager1Delegate;", "Landroidx/viewpager/widget/ViewPager$OnPageChangeListener;", "Lcom/angcyo/tablayout/ViewPagerDelegate;", "viewPager", "Landroidx/viewpager/widget/ViewPager;", "dslTabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "forceSmoothScroll", "", "(Landroidx/viewpager/widget/ViewPager;Lcom/angcyo/tablayout/DslTabLayout;Ljava/lang/Boolean;)V", "getDslTabLayout", "()Lcom/angcyo/tablayout/DslTabLayout;", "getForceSmoothScroll", "()Ljava/lang/Boolean;", "Ljava/lang/Boolean;", "getViewPager", "()Landroidx/viewpager/widget/ViewPager;", "onGetCurrentItem", "", "onPageScrollStateChanged", "", "state", "onPageScrolled", "position", "positionOffset", "", "positionOffsetPixels", "onPageSelected", "onSetCurrentItem", "fromIndex", "toIndex", "reselect", "fromUser", "Companion", "ViewPager1Delegate_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public class ViewPager1Delegate implements ViewPager.OnPageChangeListener, ViewPagerDelegate {

    /* renamed from: c */
    @NotNull
    public static final C3206a f8794c = new C3206a(null);

    /* renamed from: e */
    @NotNull
    public final ViewPager f8795e;

    /* renamed from: f */
    @Nullable
    public final DslTabLayout f8796f;

    /* renamed from: g */
    @Nullable
    public final Boolean f8797g;

    @Metadata(m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J)\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\u0010\u0007\u001a\u0004\u0018\u00010\b2\n\b\u0002\u0010\t\u001a\u0004\u0018\u00010\n¢\u0006\u0002\u0010\u000b¨\u0006\f"}, m5311d2 = {"Lcom/angcyo/tablayout/delegate/ViewPager1Delegate$Companion;", "", "()V", "install", "Lcom/angcyo/tablayout/delegate/ViewPager1Delegate;", "viewPager", "Landroidx/viewpager/widget/ViewPager;", "dslTabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "forceSmoothScroll", "", "(Landroidx/viewpager/widget/ViewPager;Lcom/angcyo/tablayout/DslTabLayout;Ljava/lang/Boolean;)Lcom/angcyo/tablayout/delegate/ViewPager1Delegate;", "ViewPager1Delegate_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.angcyo.tablayout.delegate.ViewPager1Delegate$a */
    public static final class C3206a {
        public C3206a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    public ViewPager1Delegate(@NotNull ViewPager viewPager, @Nullable DslTabLayout dslTabLayout, @Nullable Boolean bool) {
        Intrinsics.checkNotNullParameter(viewPager, "viewPager");
        this.f8795e = viewPager;
        this.f8796f = dslTabLayout;
        this.f8797g = bool;
        viewPager.addOnPageChangeListener(this);
        if (dslTabLayout == null) {
            return;
        }
        dslTabLayout.setupViewPager(this);
    }

    @Override // com.angcyo.tablayout.ViewPagerDelegate
    /* renamed from: a */
    public void mo642a(int i2, int i3, boolean z, boolean z2) {
        if (z2) {
            Boolean bool = this.f8797g;
            boolean z3 = true;
            if (bool != null) {
                z3 = bool.booleanValue();
            } else if (Math.abs(i3 - i2) > 1) {
                z3 = false;
            }
            this.f8795e.setCurrentItem(i3, z3);
        }
    }

    @Override // com.angcyo.tablayout.ViewPagerDelegate
    /* renamed from: b */
    public int mo643b() {
        return this.f8795e.getCurrentItem();
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrollStateChanged(int state) {
        DslTabLayout dslTabLayout = this.f8796f;
        if (dslTabLayout == null) {
            return;
        }
        dslTabLayout.f8757O = state;
        if (state == 0) {
            dslTabLayout.m3863a();
            dslTabLayout.getDslSelector().m665h();
        }
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
        DslTabLayout dslTabLayout = this.f8796f;
        if (dslTabLayout == null) {
            return;
        }
        dslTabLayout.m3871k(position, positionOffset);
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageSelected(int position) {
        DslTabLayout dslTabLayout = this.f8796f;
        if (dslTabLayout == null) {
            return;
        }
        dslTabLayout.m3874n(position, true, false);
    }
}
