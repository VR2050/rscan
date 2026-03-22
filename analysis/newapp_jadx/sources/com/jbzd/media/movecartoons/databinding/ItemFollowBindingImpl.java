package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ToggleButton;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.CompoundButtonBindingAdapter;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.FollowItem;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class ItemFollowBindingImpl extends ItemFollowBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.civ_avatar, 2);
        sparseIntArray.put(R.id.tv_postdetail_nickname, 3);
        sparseIntArray.put(R.id.itv_item_follow_state, 4);
    }

    public ItemFollowBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 5, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        FollowItem followItem = this.mItem;
        boolean z = false;
        long j3 = j2 & 3;
        if (j3 != 0 && followItem != null) {
            z = followItem.isFollow();
        }
        if (j3 != 0) {
            CompoundButtonBindingAdapter.setChecked(this.btnFollow, z);
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

    @Override // com.jbzd.media.movecartoons.databinding.ItemFollowBinding
    public void setItem(@Nullable FollowItem followItem) {
        this.mItem = followItem;
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
        setItem((FollowItem) obj);
        return true;
    }

    private ItemFollowBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (ToggleButton) objArr[1], (ShapeableImageView) objArr[2], (FollowTextView) objArr[4], (LinearLayout) objArr[0], (TextView) objArr[3]);
        this.mDirtyFlags = -1L;
        this.btnFollow.setTag(null);
        this.llItemFollow.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
