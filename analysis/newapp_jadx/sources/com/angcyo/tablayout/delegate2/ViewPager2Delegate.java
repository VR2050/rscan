package com.angcyo.tablayout.delegate2;

import androidx.viewpager2.widget.ViewPager2;
import com.angcyo.tablayout.ViewPagerDelegate;
import kotlin.Metadata;

@Metadata(m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u0007\n\u0002\b\t\b\u0016\u0018\u0000 !2\u00020\u00012\u00020\u0002:\u0001!B#\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\b\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u0012\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0002\u0010\tJ\b\u0010\u0011\u001a\u00020\u0012H\u0016J\u0010\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0012H\u0016J \u0010\u0016\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u00122\u0006\u0010\u0018\u001a\u00020\u00192\u0006\u0010\u001a\u001a\u00020\u0012H\u0016J\u0010\u0010\u001b\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0012H\u0016J(\u0010\u001c\u001a\u00020\u00142\u0006\u0010\u001d\u001a\u00020\u00122\u0006\u0010\u001e\u001a\u00020\u00122\u0006\u0010\u001f\u001a\u00020\b2\u0006\u0010 \u001a\u00020\bH\u0016R\u0013\u0010\u0005\u001a\u0004\u0018\u00010\u0006¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR\u0015\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\n\n\u0002\u0010\u000e\u001a\u0004\b\f\u0010\rR\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010¨\u0006\""}, m5311d2 = {"Lcom/angcyo/tablayout/delegate2/ViewPager2Delegate;", "Landroidx/viewpager2/widget/ViewPager2$OnPageChangeCallback;", "Lcom/angcyo/tablayout/ViewPagerDelegate;", "viewPager", "Landroidx/viewpager2/widget/ViewPager2;", "dslTabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "forceSmoothScroll", "", "(Landroidx/viewpager2/widget/ViewPager2;Lcom/angcyo/tablayout/DslTabLayout;Ljava/lang/Boolean;)V", "getDslTabLayout", "()Lcom/angcyo/tablayout/DslTabLayout;", "getForceSmoothScroll", "()Ljava/lang/Boolean;", "Ljava/lang/Boolean;", "getViewPager", "()Landroidx/viewpager2/widget/ViewPager2;", "onGetCurrentItem", "", "onPageScrollStateChanged", "", "state", "onPageScrolled", "position", "positionOffset", "", "positionOffsetPixels", "onPageSelected", "onSetCurrentItem", "fromIndex", "toIndex", "reselect", "fromUser", "Companion", "ViewPager2Delegate_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public class ViewPager2Delegate extends ViewPager2.OnPageChangeCallback implements ViewPagerDelegate {
    @Override // com.angcyo.tablayout.ViewPagerDelegate
    /* renamed from: a */
    public void mo642a(int i2, int i3, boolean z, boolean z2) {
        if (z2) {
            Math.abs(i3 - i2);
            throw null;
        }
    }

    @Override // com.angcyo.tablayout.ViewPagerDelegate
    /* renamed from: b */
    public int mo643b() {
        throw null;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback
    public void onPageScrollStateChanged(int state) {
    }

    @Override // androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
    }

    @Override // androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback
    public void onPageSelected(int position) {
    }
}
