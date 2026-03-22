package com.jbzd.media.movecartoons.databinding;

import android.util.SparseIntArray;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.LinearLayoutCompat;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.p396ui.accountvoucher.FindActivity;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p006a.p007a.p008a.p014p.p015a.ViewOnClickListenerC0910a;

/* loaded from: classes2.dex */
public class ActFindBindingImpl extends ActFindBinding implements ViewOnClickListenerC0910a.a {

    @Nullable
    private static final ViewDataBinding.IncludedLayouts sIncludes = null;

    @Nullable
    private static final SparseIntArray sViewsWithIds;

    @Nullable
    private final View.OnClickListener mCallback1;

    @Nullable
    private final View.OnClickListener mCallback2;

    @Nullable
    private final View.OnClickListener mCallback3;
    private long mDirtyFlags;

    @NonNull
    private final LinearLayoutCompat mboundView0;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sViewsWithIds = sparseIntArray;
        sparseIntArray.put(R.id.tvEmail, 4);
    }

    public ActFindBindingImpl(@Nullable DataBindingComponent dataBindingComponent, @NonNull View view) {
        this(dataBindingComponent, view, ViewDataBinding.mapBindings(dataBindingComponent, view, 5, sIncludes, sViewsWithIds));
    }

    @Override // p005b.p006a.p007a.p008a.p014p.p015a.ViewOnClickListenerC0910a.a
    public final void _internalCallbackOnClick(int i2, View view) {
        FindActivity.ItemClick itemClick;
        if (i2 == 1) {
            FindActivity.ItemClick itemClick2 = FindActivity.ItemClick.INSTANCE;
            if (itemClick2 != null) {
                itemClick2.onClick(view);
                return;
            }
            return;
        }
        if (i2 != 2) {
            if (i2 == 3 && (itemClick = FindActivity.ItemClick.INSTANCE) != null) {
                itemClick.onClick(view);
                return;
            }
            return;
        }
        FindActivity.ItemClick itemClick3 = FindActivity.ItemClick.INSTANCE;
        if (itemClick3 != null) {
            itemClick3.onClick(view);
        }
    }

    @Override // androidx.databinding.ViewDataBinding
    public void executeBindings() {
        long j2;
        synchronized (this) {
            j2 = this.mDirtyFlags;
            this.mDirtyFlags = 0L;
        }
        if ((j2 & 1) != 0) {
            this.layoutFindEmail.setOnClickListener(this.mCallback3);
            this.layoutFindService.setOnClickListener(this.mCallback2);
            this.layoutRetrieveAccount.setOnClickListener(this.mCallback1);
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
            this.mDirtyFlags = 1L;
        }
        requestRebind();
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean onFieldChange(int i2, Object obj, int i3) {
        return false;
    }

    @Override // androidx.databinding.ViewDataBinding
    public boolean setVariable(int i2, @Nullable Object obj) {
        return true;
    }

    private ActFindBindingImpl(DataBindingComponent dataBindingComponent, View view, Object[] objArr) {
        super(dataBindingComponent, view, 0, (LinearLayoutCompat) objArr[3], (LinearLayoutCompat) objArr[2], (LinearLayoutCompat) objArr[1], (TextView) objArr[4]);
        this.mDirtyFlags = -1L;
        this.layoutFindEmail.setTag(null);
        this.layoutFindService.setTag(null);
        this.layoutRetrieveAccount.setTag(null);
        LinearLayoutCompat linearLayoutCompat = (LinearLayoutCompat) objArr[0];
        this.mboundView0 = linearLayoutCompat;
        linearLayoutCompat.setTag(null);
        setRootTag(view);
        this.mCallback3 = new ViewOnClickListenerC0910a(this, 3);
        this.mCallback1 = new ViewOnClickListenerC0910a(this, 1);
        this.mCallback2 = new ViewOnClickListenerC0910a(this, 2);
        invalidateAll();
    }
}
