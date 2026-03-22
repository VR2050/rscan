package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ItemNovelLayoutBindingImpl extends ItemNovelLayoutBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    @Nullable
    private final VideoItemCoverHotBinding mboundView1;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.item_parent, 3);
        sparseIntArray.put(R.id.img_cover, 4);
        sparseIntArray.put(R.id.iv_novel_audio, 5);
        sparseIntArray.put(R.id.ll_name, 6);
        sparseIntArray.put(R.id.tv_novel_name, 7);
        sparseIntArray.put(R.id.tv_novel_category_subtitle, 8);
    }

    public ItemNovelLayoutBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 9, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        synchronized (this) {
            this.mDirtyFlags = 0L;
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemNovelLayoutBinding
    public void setItem(@Nullable NovelItemsBean novelItemsBean) {
        this.mItem = novelItemsBean;
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (1 != i2) {
            return false;
        }
        setItem((NovelItemsBean) obj);
        return true;
    }

    private ItemNovelLayoutBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (ShapeableImageView) objArr[4], (ScaleRelativeLayout) objArr[3], (ImageView) objArr[5], (LinearLayout) objArr[6], (RelativeLayout) objArr[1], (ConstraintLayout) objArr[0], (TextView) objArr[8], (TextView) objArr[7]);
        this.mDirtyFlags = -1L;
        this.mboundView1 = objArr[2] != null ? VideoItemCoverHotBinding.bind((View) objArr[2]) : null;
        this.rlCoverOption.setTag(null);
        this.root.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
