package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.CompoundButtonBindingAdapter;
import androidx.databinding.adapters.TextViewBindingAdapter;
import com.jbzd.media.movecartoons.bean.response.GroupBean;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* loaded from: classes2.dex */
public class ItemPayTypeVerticalBindingImpl extends ItemPayTypeVerticalBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds = null;
    private long mDirtyFlags;

    public ItemPayTypeVerticalBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 4, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        String str;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        GroupBean.PaymentsBean paymentsBean = this.mItem;
        boolean z = false;
        long j3 = j2 & 3;
        String str2 = null;
        if (j3 == 0 || paymentsBean == null) {
            str = null;
        } else {
            String payment_name = paymentsBean.getPayment_name();
            z = paymentsBean.getIsChecked();
            str2 = paymentsBean.getPayment_ico();
            str = payment_name;
        }
        if (j3 != 0) {
            CompoundButtonBindingAdapter.setChecked(this.checkbox, z);
            C2354n.m2535z1(this.imgPayIcon, str2);
            TextViewBindingAdapter.setText(this.txtPayName, str);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemPayTypeVerticalBinding
    public void setItem(@Nullable GroupBean.PaymentsBean paymentsBean) {
        this.mItem = paymentsBean;
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
        setItem((GroupBean.PaymentsBean) obj);
        return true;
    }

    private ItemPayTypeVerticalBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (CheckBox) objArr[3], (ImageView) objArr[1], (ConstraintLayout) objArr[0], (TextView) objArr[2]);
        this.mDirtyFlags = -1L;
        this.checkbox.setTag(null);
        this.imgPayIcon.setTag(null);
        this.root.setTag(null);
        this.txtPayName.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
