package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p006a.p007a.p008a.p013o.C0908b;

/* loaded from: classes2.dex */
public abstract class ItemMemberRightsBinding extends ViewDataBinding {

    @NonNull
    public final ImageView imgRightsIcon;

    @Bindable
    public C0908b mItem;

    public ItemMemberRightsBinding(Object obj, View view, int i2, ImageView imageView) {
        super(obj, view, i2);
        this.imgRightsIcon = imageView;
    }

    public static ItemMemberRightsBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ItemMemberRightsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public C0908b getItem() {
        return this.mItem;
    }

    public abstract void setItem(@Nullable C0908b c0908b);

    @Deprecated
    public static ItemMemberRightsBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ItemMemberRightsBinding) ViewDataBinding.bind(obj, view, R.layout.item_member_rights);
    }

    @NonNull
    @Deprecated
    public static ItemMemberRightsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ItemMemberRightsBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_member_rights, viewGroup, z, obj);
    }

    @NonNull
    public static ItemMemberRightsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ItemMemberRightsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ItemMemberRightsBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.item_member_rights, null, false, obj);
    }
}
