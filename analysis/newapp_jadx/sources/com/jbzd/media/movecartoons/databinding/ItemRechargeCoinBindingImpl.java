package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import com.jbzd.media.movecartoons.bean.response.RechargeBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ItemRechargeCoinBindingImpl extends ItemRechargeCoinBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds = null;
    private long mDirtyFlags;

    public ItemRechargeCoinBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 5, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        String str;
        String str2;
        boolean z;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        RechargeBean.ProductsBean productsBean = this.mItem;
        long j3 = j2 & 3;
        String str3 = null;
        if (j3 != 0) {
            if (productsBean != null) {
                String num = productsBean.getNum();
                String priceZero = productsBean.getPriceZero();
                z = productsBean.hasGift();
                str3 = priceZero;
                str2 = num;
            } else {
                str2 = null;
                z = false;
            }
            if (j3 != 0) {
                j2 |= z ? 8L : 4L;
            }
            String string = this.tvPrice.getResources().getString(R.string.payment_price, str3);
            r10 = z ? 0 : 4;
            str = string;
            str3 = str2;
        } else {
            str = null;
        }
        if ((j2 & 3) != 0) {
            this.promotionTips.setVisibility(r10);
            TextViewBindingAdapter.setText(this.tvCoin, str3);
            TextViewBindingAdapter.setText(this.tvPrice, str);
            this.tvTagTui.setVisibility(r10);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemRechargeCoinBinding
    public void setItem(@Nullable RechargeBean.ProductsBean productsBean) {
        this.mItem = productsBean;
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
        setItem((RechargeBean.ProductsBean) obj);
        return true;
    }

    private ItemRechargeCoinBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (TextView) objArr[4], (ConstraintLayout) objArr[0], (TextView) objArr[2], (TextView) objArr[3], (TextView) objArr[1]);
        this.mDirtyFlags = -1L;
        this.promotionTips.setTag(null);
        this.root.setTag(null);
        this.tvCoin.setTag(null);
        this.tvPrice.setTag(null);
        this.tvTagTui.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
