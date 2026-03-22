package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import com.jbzd.media.movecartoons.bean.response.ExchangeLogBean;

/* loaded from: classes2.dex */
public class ItemExchangeBindingImpl extends ItemExchangeBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds = null;
    private long mDirtyFlags;

    @NonNull
    private final LinearLayout mboundView0;

    public ItemExchangeBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 4, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        String str;
        String str2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        ExchangeLogBean exchangeLogBean = this.mItem;
        long j3 = j2 & 3;
        String str3 = null;
        if (j3 == 0 || exchangeLogBean == null) {
            str = null;
            str2 = null;
        } else {
            String tips = exchangeLogBean.getTips();
            String code = exchangeLogBean.getCode();
            str2 = exchangeLogBean.getLabel();
            str3 = code;
            str = tips;
        }
        if (j3 != 0) {
            TextViewBindingAdapter.setText(this.tvCode, str3);
            TextViewBindingAdapter.setText(this.tvDay, str);
            TextViewBindingAdapter.setText(this.tvTime, str2);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemExchangeBinding
    public void setItem(@Nullable ExchangeLogBean exchangeLogBean) {
        this.mItem = exchangeLogBean;
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
        setItem((ExchangeLogBean) obj);
        return true;
    }

    private ItemExchangeBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (TextView) objArr[1], (TextView) objArr[2], (TextView) objArr[3]);
        this.mDirtyFlags = -1L;
        LinearLayout linearLayout = (LinearLayout) objArr[0];
        this.mboundView0 = linearLayout;
        linearLayout.setTag(null);
        this.tvCode.setTag(null);
        this.tvDay.setTag(null);
        this.tvTime.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
