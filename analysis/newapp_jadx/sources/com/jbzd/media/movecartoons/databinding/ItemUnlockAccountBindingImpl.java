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
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* loaded from: classes2.dex */
public class ItemUnlockAccountBindingImpl extends ItemUnlockAccountBinding {

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
        sparseIntArray.put(R.id.iv_more, 4);
    }

    public ItemUnlockAccountBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 5, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        String str;
        String str2;
        String str3;
        String str4;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        UserInfoBean userInfoBean = this.mItem;
        long j3 = j2 & 3;
        String str5 = null;
        if (j3 != 0) {
            if (userInfoBean != null) {
                String str6 = userInfoBean.fans;
                String str7 = userInfoBean.username;
                String str8 = userInfoBean.img;
                str2 = str7;
                str3 = str6;
                str5 = userInfoBean.share_num;
                str4 = str8;
            } else {
                str3 = null;
                str2 = null;
                str4 = null;
            }
            str = this.tvCount.getResources().getString(R.string.account_work_fans, str5, str3);
            str5 = str4;
        } else {
            str = null;
            str2 = null;
        }
        if (j3 != 0) {
            C2354n.m2535z1(this.ivMineAvatar, str5);
            TextViewBindingAdapter.setText(this.tvCount, str);
            TextViewBindingAdapter.setText(this.tvName, str2);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemUnlockAccountBinding
    public void setItem(@Nullable UserInfoBean userInfoBean) {
        this.mItem = userInfoBean;
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
        setItem((UserInfoBean) obj);
        return true;
    }

    private ItemUnlockAccountBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (ShapeableImageView) objArr[1], (ImageView) objArr[4], (TextView) objArr[3], (TextView) objArr[2]);
        this.mDirtyFlags = -1L;
        this.ivMineAvatar.setTag(null);
        ConstraintLayout constraintLayout = (ConstraintLayout) objArr[0];
        this.mboundView0 = constraintLayout;
        constraintLayout.setTag(null);
        this.tvCount.setTag(null);
        this.tvName.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
