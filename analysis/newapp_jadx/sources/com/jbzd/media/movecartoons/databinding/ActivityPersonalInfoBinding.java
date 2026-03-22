package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.databinding.Bindable;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public abstract class ActivityPersonalInfoBinding extends ViewDataBinding {

    @NonNull
    public final LinearLayout bottomBtn;

    @NonNull
    public final TextView btnSubmit;

    @NonNull
    public final AppCompatEditText editNickName;

    @NonNull
    public final ConstraintLayout groupSexy;

    @Bindable
    public UserInfoBean mUserInfo;

    @NonNull
    public final CheckBox radioSexFemale;

    @NonNull
    public final CheckBox radioSexMale;

    public ActivityPersonalInfoBinding(Object obj, View view, int i2, LinearLayout linearLayout, TextView textView, AppCompatEditText appCompatEditText, ConstraintLayout constraintLayout, CheckBox checkBox, CheckBox checkBox2) {
        super(obj, view, i2);
        this.bottomBtn = linearLayout;
        this.btnSubmit = textView;
        this.editNickName = appCompatEditText;
        this.groupSexy = constraintLayout;
        this.radioSexFemale = checkBox;
        this.radioSexMale = checkBox2;
    }

    public static ActivityPersonalInfoBinding bind(@NonNull View view) {
        return bind(view, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    public static ActivityPersonalInfoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        return inflate(layoutInflater, viewGroup, z, DataBindingUtil.getDefaultComponent());
    }

    @Nullable
    public UserInfoBean getUserInfo() {
        return this.mUserInfo;
    }

    public abstract void setUserInfo(@Nullable UserInfoBean userInfoBean);

    @Deprecated
    public static ActivityPersonalInfoBinding bind(@NonNull View view, @Nullable Object obj) {
        return (ActivityPersonalInfoBinding) ViewDataBinding.bind(obj, view, R.layout.activity_personal_info);
    }

    @NonNull
    @Deprecated
    public static ActivityPersonalInfoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z, @Nullable Object obj) {
        return (ActivityPersonalInfoBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.activity_personal_info, viewGroup, z, obj);
    }

    @NonNull
    public static ActivityPersonalInfoBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, DataBindingUtil.getDefaultComponent());
    }

    @NonNull
    @Deprecated
    public static ActivityPersonalInfoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable Object obj) {
        return (ActivityPersonalInfoBinding) ViewDataBinding.inflateInternal(layoutInflater, R.layout.activity_personal_info, null, false, obj);
    }
}
