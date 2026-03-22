package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import com.google.android.material.imageview.ShapeableImageView;
import kotlin.jvm.internal.Intrinsics;
import p005b.p006a.p007a.p008a.p013o.C0908b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* loaded from: classes2.dex */
public class ItemMineGridBindingImpl extends ItemMineGridBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds = null;
    private long mDirtyFlags;

    public ItemMineGridBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 4, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        int i2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        String str = null;
        C0908b c0908b = this.mItem;
        long j3 = j2 & 3;
        int i3 = 0;
        if (j3 == 0 || c0908b == null) {
            i2 = 0;
        } else {
            i3 = c0908b.f362d;
            str = c0908b.f360b;
            i2 = c0908b.f359a;
        }
        if (j3 != 0) {
            ShapeableImageView imageView = this.imgBg;
            Intrinsics.checkNotNullParameter(imageView, "imageView");
            imageView.setImageResource(i3);
            C2354n.m2532y1(this.imgItemCoin, i2);
            TextViewBindingAdapter.setText(this.tvItemName, str);
        }
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemMineGridBinding
    public void setItem(@Nullable C0908b c0908b) {
        this.mItem = c0908b;
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
        setItem((C0908b) obj);
        return true;
    }

    private ItemMineGridBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (ShapeableImageView) objArr[1], (ImageView) objArr[2], (ConstraintLayout) objArr[0], (TextView) objArr[3]);
        this.mDirtyFlags = -1L;
        this.imgBg.setTag(null);
        this.imgItemCoin.setTag(null);
        this.root.setTag(null);
        this.tvItemName.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
