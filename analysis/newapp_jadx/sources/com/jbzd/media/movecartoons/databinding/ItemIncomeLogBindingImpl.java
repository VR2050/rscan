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
import com.jbzd.media.movecartoons.bean.response.IncomeLogBean;

/* loaded from: classes2.dex */
public class ItemIncomeLogBindingImpl extends ItemIncomeLogBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds = null;
    private long mDirtyFlags;

    @NonNull
    private final ConstraintLayout mboundView0;

    public ItemIncomeLogBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
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
        IncomeLogBean incomeLogBean = this.mItem;
        long j3 = j2 & 3;
        String str3 = null;
        if (j3 == 0 || incomeLogBean == null) {
            str = null;
            str2 = null;
        } else {
            str3 = incomeLogBean.title;
            str = incomeLogBean.point;
            str2 = incomeLogBean.created_at;
        }
        if (j3 != 0) {
            TextViewBindingAdapter.setText(this.tvName, str3);
            TextViewBindingAdapter.setText(this.tvNum, str);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemIncomeLogBinding
    public void setItem(@Nullable IncomeLogBean incomeLogBean) {
        this.mItem = incomeLogBean;
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
        setItem((IncomeLogBean) obj);
        return true;
    }

    private ItemIncomeLogBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (TextView) objArr[1], (TextView) objArr[2], (TextView) objArr[3]);
        this.mDirtyFlags = -1L;
        ConstraintLayout constraintLayout = (ConstraintLayout) objArr[0];
        this.mboundView0 = constraintLayout;
        constraintLayout.setTag(null);
        this.tvName.setTag(null);
        this.tvNum.setTag(null);
        this.tvTime.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
