package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.appcompat.widget.LinearLayoutCompat;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.CompoundButtonBindingAdapter;
import androidx.databinding.adapters.TextViewBindingAdapter;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ActivityPersonalInfoBindingImpl extends ActivityPersonalInfoBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    @NonNull
    private final LinearLayoutCompat mboundView0;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.group_sexy, 4);
        sparseIntArray.put(R.id.bottom_btn, 5);
        sparseIntArray.put(R.id.btn_submit, 6);
    }

    public ActivityPersonalInfoBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 7, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        boolean z;
        int i2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        UserInfoBean userInfoBean = this.mUserInfo;
        String str = null;
        long j3 = j2 & 3;
        if (j3 != 0) {
            if (userInfoBean != null) {
                i2 = userInfoBean.sexy();
                str = userInfoBean.nickname;
            } else {
                i2 = 0;
            }
            boolean z2 = i2 == 2;
            z = i2 == 1;
            r6 = z2;
        } else {
            z = false;
        }
        if (j3 != 0) {
            TextViewBindingAdapter.setText(this.editNickName, str);
            CompoundButtonBindingAdapter.setChecked(this.radioSexFemale, r6);
            CompoundButtonBindingAdapter.setChecked(this.radioSexMale, z);
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

    @Override // com.jbzd.media.movecartoons.databinding.ActivityPersonalInfoBinding
    public void setUserInfo(@Nullable UserInfoBean userInfoBean) {
        this.mUserInfo = userInfoBean;
        synchronized (this) {
            this.mDirtyFlags |= 1;
        }
        notifyPropertyChanged(4);
        super.requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (4 != i2) {
            return false;
        }
        setUserInfo((UserInfoBean) obj);
        return true;
    }

    private ActivityPersonalInfoBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (LinearLayout) objArr[5], (TextView) objArr[6], (AppCompatEditText) objArr[1], (ConstraintLayout) objArr[4], (CheckBox) objArr[3], (CheckBox) objArr[2]);
        this.mDirtyFlags = -1L;
        this.editNickName.setTag(null);
        LinearLayoutCompat linearLayoutCompat = (LinearLayoutCompat) objArr[0];
        this.mboundView0 = linearLayoutCompat;
        linearLayoutCompat.setTag(null);
        this.radioSexFemale.setTag(null);
        this.radioSexMale.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
