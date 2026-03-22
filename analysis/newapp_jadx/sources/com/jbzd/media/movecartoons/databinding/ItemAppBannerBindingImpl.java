package com.jbzd.media.movecartoons.databinding;

import android.content.Context;
import android.util.SparseIntArray;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import com.youth.banner.Banner;
import java.util.ArrayList;
import java.util.Objects;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.internal.Intrinsics;
import p005b.p006a.p007a.p008a.p013o.C0907a;

/* loaded from: classes2.dex */
public class ItemAppBannerBindingImpl extends ItemAppBannerBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds = null;
    private long mDirtyFlags;

    @NonNull
    private final ConstraintLayout mboundView0;

    public ItemAppBannerBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 2, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        C0907a c0907a = this.mItem;
        if ((j2 & 3) == 0) {
            return;
        }
        Banner banner = this.banner;
        Intrinsics.checkNotNullParameter(banner, "banner");
        Intrinsics.checkNotNullParameter(null, "adList");
        Context context = banner.getContext();
        Objects.requireNonNull(context, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
        banner.addBannerLifecycleObserver((AppCompatActivity) context);
        Context context2 = banner.getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "context");
        new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(null, 10));
        throw null;
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean hasPendingBindings() {
        synchronized (this) {
            return this.mDirtyFlags != 0;
        }
    }

    @Override // androidx.databinding.ViewDataBinding
    public void invalidateAll() {
        synchronized (this) {
            this.mDirtyFlags = 2L;
        }
        requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean onFieldChange(int i2, Object obj, int i3) {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.databinding.ItemAppBannerBinding
    public void setItem(@Nullable C0907a c0907a) {
        this.mItem = c0907a;
        synchronized (this) {
            this.mDirtyFlags |= 1;
        }
        notifyPropertyChanged(1);
        super.requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (1 != i2) {
            return false;
        }
        setItem((C0907a) obj);
        return true;
    }

    private ItemAppBannerBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (Banner) objArr[1]);
        this.mDirtyFlags = -1L;
        this.banner.setTag(null);
        ConstraintLayout constraintLayout = (ConstraintLayout) objArr[0];
        this.mboundView0 = constraintLayout;
        constraintLayout.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
