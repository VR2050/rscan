package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.LinearLayoutCompat;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ActFindBinding extends ViewDataBinding {

    @NonNull
    public final LinearLayoutCompat layoutFindEmail;

    @NonNull
    public final LinearLayoutCompat layoutFindService;

    @NonNull
    public final LinearLayoutCompat layoutRetrieveAccount;

    @NonNull
    public final TextView tvEmail;

    public ActFindBinding(Object obj, View view, int i2, LinearLayoutCompat linearLayoutCompat, LinearLayoutCompat linearLayoutCompat2, LinearLayoutCompat linearLayoutCompat3, TextView textView) {
        super(obj, view, i2);
        this.layoutFindEmail = linearLayoutCompat;
        this.layoutFindService = linearLayoutCompat2;
        this.layoutRetrieveAccount = linearLayoutCompat3;
        this.tvEmail = textView;
    }

    public static ActFindBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ActFindBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Deprecated
    public static ActFindBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ActFindBinding) ViewDataBinding.bind(obj, view, R.layout.act_find);
    }

    @NonNull
    @Deprecated
    public static ActFindBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ActFindBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_find, viewGroup, z, obj);
    }

    @NonNull
    public static ActFindBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ActFindBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ActFindBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.act_find, null, false, obj);
    }
}
