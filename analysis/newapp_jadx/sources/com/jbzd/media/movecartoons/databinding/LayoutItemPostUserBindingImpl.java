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
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* loaded from: classes2.dex */
public class LayoutItemPostUserBindingImpl extends LayoutItemPostUserBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.itv_postuser_follow, 6);
    }

    public LayoutItemPostUserBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 7, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        String str;
        int i2;
        String str2;
        boolean z;
        boolean z2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        PostListBean.UserBean userBean = this.mUserBean;
        String str3 = this.mTime;
        long j3 = j2 & 5;
        String str4 = null;
        if (j3 != 0) {
            if (userBean != null) {
                z2 = userBean.isUp();
                str4 = userBean.getNickname();
                str2 = userBean.getImg();
                z = userBean.isVip();
            } else {
                str2 = null;
                z = false;
                z2 = false;
            }
            if (j3 != 0) {
                j2 |= z2 ? 64L : 32L;
            }
            if ((j2 & 5) != 0) {
                j2 |= z ? 16L : 8L;
            }
            int i3 = z2 ? 0 : 8;
            r12 = z ? 0 : 8;
            str = str4;
            str4 = str2;
            int i4 = r12;
            r12 = i3;
            i2 = i4;
        } else {
            str = null;
            i2 = 0;
        }
        long j4 = 6 & j2;
        if ((j2 & 5) != 0) {
            this.imgUp.setVisibility(r12);
            this.imgVip.setVisibility(i2);
            C2354n.m2535z1(this.ivMineAvatar, str4);
            TextViewBindingAdapter.setText(this.txtName, str);
        }
        if (j4 != 0) {
            TextViewBindingAdapter.setText(this.txtReleaseTime, str3);
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
            this.mDirtyFlags = 4L;
        }
        requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean onFieldChange(int i2, Object obj, int i3) {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.databinding.LayoutItemPostUserBinding
    public void setTime(@Nullable String str) {
        this.mTime = str;
        synchronized (this) {
            this.mDirtyFlags |= 2;
        }
        notifyPropertyChanged(2);
        super.requestRebind();
    }

    @Override // com.jbzd.media.movecartoons.databinding.LayoutItemPostUserBinding
    public void setUserBean(@Nullable PostListBean.UserBean userBean) {
        this.mUserBean = userBean;
        synchronized (this) {
            this.mDirtyFlags |= 1;
        }
        notifyPropertyChanged(3);
        super.requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (3 == i2) {
            setUserBean((PostListBean.UserBean) obj);
        } else {
            if (2 != i2) {
                return false;
            }
            setTime((String) obj);
        }
        return true;
    }

    private LayoutItemPostUserBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (ImageView) objArr[5], (ImageView) objArr[4], (FollowTextView) objArr[6], (ShapeableImageView) objArr[1], (ConstraintLayout) objArr[0], (TextView) objArr[2], (TextView) objArr[3]);
        this.mDirtyFlags = -1L;
        this.imgUp.setTag(null);
        this.imgVip.setTag(null);
        this.ivMineAvatar.setTag(null);
        this.layoutUserInfo.setTag(null);
        this.txtName.setTag(null);
        this.txtReleaseTime.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
