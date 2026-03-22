package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import androidx.databinding.adapters.TextViewBindingAdapter;
import androidx.lifecycle.LifecycleOwner;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.view.PostFileView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p006a.p007a.p008a.p009a.C0843e0;

/* loaded from: classes2.dex */
public class ItemPostLayoutBindingImpl extends ItemPostLayoutBinding {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes;

    @Nullable
    private static final SparseIntArray sViewsWithIds;
    private long mDirtyFlags;

    @Nullable
    private final LayoutItemPostUserBinding mboundView0;

    static {
        ViewDataBinding.IncludedLayouts includedLayouts = new ViewDataBinding.IncludedLayouts(13);
        sIncludes = includedLayouts;
        includedLayouts.setIncludes(0, new String[]{"layout_item_post_user"}, new int[]{6}, new int[]{R.layout.layout_item_post_user});
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.layout_post_file, 7);
        sparseIntArray.put(R.id.rv_tag_post, 8);
        sparseIntArray.put(R.id.layout_click, 9);
        sparseIntArray.put(R.id.layout_comment, 10);
        sparseIntArray.put(R.id.layout_praise, 11);
        sparseIntArray.put(R.id.layout_share, 12);
    }

    public ItemPostLayoutBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 13, sIncludes, sViewsWithIds));
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        String str;
        String str2;
        PostListBean.UserBean userBean;
        String str3;
        String str4;
        String str5;
        String str6;
        String str7;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        PostListBean postListBean = this.mItem;
        long j3 = j2 & 3;
        String str8 = null;
        if (j3 != 0) {
            if (postListBean != null) {
                str8 = postListBean.getLove();
                str6 = postListBean.getTime();
                userBean = postListBean.getUser();
                str7 = postListBean.getClick();
                str4 = postListBean.getComment();
                str5 = postListBean.getTitle();
                str = postListBean.getContent();
            } else {
                str = null;
                str6 = null;
                userBean = null;
                str7 = null;
                str4 = null;
                str5 = null;
            }
            String m182a = C0843e0.m182a(str8);
            str3 = C0843e0.m182a(str7);
            boolean z = (str != null ? str.length() : 0) > 0;
            if (j3 != 0) {
                j2 |= z ? 8L : 4L;
            }
            r10 = z ? 0 : 8;
            str8 = str6;
            str2 = m182a;
        } else {
            str = null;
            str2 = null;
            userBean = null;
            str3 = null;
            str4 = null;
            str5 = null;
        }
        if ((j2 & 3) != 0) {
            this.mboundView0.setTime(str8);
            this.mboundView0.setUserBean(userBean);
            TextViewBindingAdapter.setText(this.txtClick, str3);
            TextViewBindingAdapter.setText(this.txtComment, str4);
            TextViewBindingAdapter.setText(this.txtContent, str);
            this.txtContent.setVisibility(r10);
            TextViewBindingAdapter.setText(this.txtNumClick, str5);
            TextViewBindingAdapter.setText(this.txtPraise, str2);
        }
        ViewDataBinding.executeBindingsOn(this.mboundView0);
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean hasPendingBindings() {
        synchronized (this) {
            if (this.mDirtyFlags != 0) {
                return true;
            }
            return this.mboundView0.hasPendingBindings();
        }
    }

    @Override // androidx.databinding.ViewDataBinding
    public void invalidateAll() {
        synchronized (this) {
            this.mDirtyFlags = 2L;
        }
        this.mboundView0.invalidateAll();
        requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean onFieldChange(int i2, Object obj, int i3) {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.databinding.ItemPostLayoutBinding
    public void setItem(@Nullable PostListBean postListBean) {
        this.mItem = postListBean;
        synchronized (this) {
            this.mDirtyFlags |= 1;
        }
        notifyPropertyChanged(1);
        super.requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public void setLifecycleOwner(@Nullable LifecycleOwner lifecycleOwner) {
        super.setLifecycleOwner(lifecycleOwner);
        this.mboundView0.setLifecycleOwner(lifecycleOwner);
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        if (1 != i2) {
            return false;
        }
        setItem((PostListBean) obj);
        return true;
    }

    private ItemPostLayoutBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (LinearLayout) objArr[9], (LinearLayout) objArr[10], (PostFileView) objArr[7], (LinearLayout) objArr[11], (LinearLayout) objArr[12], (ConstraintLayout) objArr[0], (RecyclerView) objArr[8], (ImageTextView) objArr[3], (ImageTextView) objArr[5], (TextView) objArr[2], (TextView) objArr[1], (ImageTextView) objArr[4]);
        this.mDirtyFlags = -1L;
        LayoutItemPostUserBinding layoutItemPostUserBinding = (LayoutItemPostUserBinding) objArr[6];
        this.mboundView0 = layoutItemPostUserBinding;
        setContainedBinding(layoutItemPostUserBinding);
        this.root.setTag(null);
        this.txtClick.setTag(null);
        this.txtComment.setTag(null);
        this.txtContent.setTag(null);
        this.txtNumClick.setTag(null);
        this.txtPraise.setTag(null);
        setRootTag(view);
        invalidateAll();
    }
}
