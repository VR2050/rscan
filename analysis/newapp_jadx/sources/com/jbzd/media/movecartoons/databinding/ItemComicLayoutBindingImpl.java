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
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsItemBean;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ItemComicLayoutBindingImpl extends ItemComicLayoutBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.img_cover, 2);
        sparseIntArray.put(R.id.tv_ad_new_comics, 3);
        sparseIntArray.put(R.id.img_stroke, 4);
        sparseIntArray.put(R.id.tv_comics_name, 5);
        sparseIntArray.put(R.id.tv_comics_category_subtitle, 6);
        sparseIntArray.put(R.id.iv_ico_type, 7);
    }

    public ItemComicLayoutBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 8, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        String str = null;
        ComicsItemBean comicsItemBean = this.mItem;
        long j3 = j2 & 3;
        if (j3 != 0 && comicsItemBean != null) {
            str = comicsItemBean.sub_title;
        }
        if (j3 != 0) {
            TextViewBindingAdapter.setText(this.txtNumClick, str);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemComicLayoutBinding
    public void setItem(@Nullable ComicsItemBean comicsItemBean) {
        this.mItem = comicsItemBean;
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
        setItem((ComicsItemBean) obj);
        return true;
    }

    private ItemComicLayoutBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (ShapeableImageView) objArr[2], (ShapeableImageView) objArr[4], (ImageView) objArr[7], (ConstraintLayout) objArr[0], (TextView) objArr[3], (TextView) objArr[6], (TextView) objArr[5], (ImageTextView) objArr[1]);
        this.mDirtyFlags = -1L;
        this.root.setTag(null);
        this.txtNumClick.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
