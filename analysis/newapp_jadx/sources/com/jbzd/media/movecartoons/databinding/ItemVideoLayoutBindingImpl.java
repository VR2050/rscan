package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ItemVideoLayoutBindingImpl extends ItemVideoLayoutBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.iv_video, 5);
        sparseIntArray.put(R.id.iv_ico_type, 6);
        sparseIntArray.put(R.id.layout_isHide_vip, 7);
        sparseIntArray.put(R.id.tv_video_type, 8);
        sparseIntArray.put(R.id.tv_name, 9);
        sparseIntArray.put(R.id.tv_video_click, 10);
    }

    public ItemVideoLayoutBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 11, sIncludes, sViewsWithIds));
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
        VideoItemBean videoItemBean = this.mItem;
        long j3 = j2 & 3;
        String str3 = null;
        if (j3 != 0) {
            if (videoItemBean != null) {
                str3 = videoItemBean.getDuration_show();
                str2 = videoItemBean.click;
                z2 = videoItemBean.isSelect;
                z = videoItemBean.getIsMoneyVideo();
            } else {
                str2 = null;
                z = false;
                z2 = false;
            }
            if (j3 != 0) {
                j2 |= z2 ? 8L : 4L;
            }
            if ((j2 & 3) != 0) {
                j2 |= z ? 32L : 16L;
            }
            i2 = z2 ? 0 : 8;
            r10 = z ? 0 : 8;
            str = str3;
            str3 = str2;
        } else {
            str = null;
            i2 = 0;
        }
        if ((j2 & 3) != 0) {
            this.imgIconMoney.setVisibility(r10);
            this.imgStroke.setVisibility(i2);
            TextViewBindingAdapter.setText(this.tvCount, str3);
            TextViewBindingAdapter.setText(this.tvDuration, str);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemVideoLayoutBinding
    public void setItem(@Nullable VideoItemBean videoItemBean) {
        this.mItem = videoItemBean;
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
        setItem((VideoItemBean) obj);
        return true;
    }

    private ItemVideoLayoutBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (ImageView) objArr[2], (ShapeableImageView) objArr[1], (ImageView) objArr[6], (ShapeableImageView) objArr[5], (LinearLayout) objArr[7], (ConstraintLayout) objArr[0], (ImageTextView) objArr[3], (TextView) objArr[4], (TextView) objArr[9], (TextView) objArr[10], (TextView) objArr[8]);
        this.mDirtyFlags = -1L;
        this.imgIconMoney.setTag(null);
        this.imgStroke.setTag(null);
        this.root.setTag(null);
        this.tvCount.setTag(null);
        this.tvDuration.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
