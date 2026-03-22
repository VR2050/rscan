package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.databinding.TitleBarLayoutBinding;

/* loaded from: classes2.dex */
public final class ActivityUserinfoSexBinding implements ViewBinding {

    @NonNull
    public final LinearLayout bottomBtn;

    @NonNull
    public final AppCompatButton btnSubmit;

    @NonNull
    public final ConstraintLayout groupSexy;

    @NonNull
    public final TitleBarLayoutBinding llTitleUserinfo;

    @NonNull
    public final CheckBox radioSexFemale;

    @NonNull
    public final CheckBox radioSexMale;

    @NonNull
    private final ConstraintLayout rootView;

    private ActivityUserinfoSexBinding(@NonNull ConstraintLayout constraintLayout, @NonNull LinearLayout linearLayout, @NonNull AppCompatButton appCompatButton, @NonNull ConstraintLayout constraintLayout2, @NonNull TitleBarLayoutBinding titleBarLayoutBinding, @NonNull CheckBox checkBox, @NonNull CheckBox checkBox2) {
        this.rootView = constraintLayout;
        this.bottomBtn = linearLayout;
        this.btnSubmit = appCompatButton;
        this.groupSexy = constraintLayout2;
        this.llTitleUserinfo = titleBarLayoutBinding;
        this.radioSexFemale = checkBox;
        this.radioSexMale = checkBox2;
    }

    @NonNull
    public static ActivityUserinfoSexBinding bind(@NonNull View view) {
        int i2 = R.id.bottom_btn;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.bottom_btn);
        if (linearLayout != null) {
            i2 = R.id.btn_submit;
            AppCompatButton appCompatButton = (AppCompatButton) view.findViewById(R.id.btn_submit);
            if (appCompatButton != null) {
                i2 = R.id.group_sexy;
                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.group_sexy);
                if (constraintLayout != null) {
                    i2 = R.id.ll_title_userinfo;
                    View findViewById = view.findViewById(R.id.ll_title_userinfo);
                    if (findViewById != null) {
                        TitleBarLayoutBinding bind = TitleBarLayoutBinding.bind(findViewById);
                        i2 = R.id.radio_sex_female;
                        CheckBox checkBox = (CheckBox) view.findViewById(R.id.radio_sex_female);
                        if (checkBox != null) {
                            i2 = R.id.radio_sex_male;
                            CheckBox checkBox2 = (CheckBox) view.findViewById(R.id.radio_sex_male);
                            if (checkBox2 != null) {
                                return new ActivityUserinfoSexBinding((ConstraintLayout) view, linearLayout, appCompatButton, constraintLayout, bind, checkBox, checkBox2);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActivityUserinfoSexBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActivityUserinfoSexBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.activity_userinfo_sex, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
