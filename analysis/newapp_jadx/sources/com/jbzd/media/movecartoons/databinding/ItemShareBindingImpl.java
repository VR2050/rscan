package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import com.jbzd.media.movecartoons.bean.response.ShareBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ItemShareBindingImpl extends ItemShareBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    @NonNull
    private final ConstraintLayout mboundView0;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.guideLeft, 4);
        sparseIntArray.put(R.id.guideRight, 5);
    }

    public ItemShareBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 6, sIncludes, sViewsWithIds));
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
        ShareBean shareBean = this.mItem;
        long j3 = j2 & 3;
        String str3 = null;
        if (j3 == 0 || shareBean == null) {
            str = null;
            str2 = null;
        } else {
            String register_at = shareBean.getRegister_at();
            String id = shareBean.getId();
            str2 = shareBean.getNickname();
            str3 = id;
            str = register_at;
        }
        if (j3 != 0) {
            TextViewBindingAdapter.setText(this.tvItemshareCode, str3);
            TextViewBindingAdapter.setText(this.tvItemshareNickname, str2);
            TextViewBindingAdapter.setText(this.tvItemshareTime, str);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemShareBinding
    public void setItem(@Nullable ShareBean shareBean) {
        this.mItem = shareBean;
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
        setItem((ShareBean) obj);
        return true;
    }

    private ItemShareBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (Guideline) objArr[4], (Guideline) objArr[5], (TextView) objArr[1], (TextView) objArr[2], (TextView) objArr[3]);
        this.mDirtyFlags = -1L;
        ConstraintLayout constraintLayout = (ConstraintLayout) objArr[0];
        this.mboundView0 = constraintLayout;
        constraintLayout.setTag(null);
        this.tvItemshareCode.setTag(null);
        this.tvItemshareNickname.setTag(null);
        this.tvItemshareTime.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
