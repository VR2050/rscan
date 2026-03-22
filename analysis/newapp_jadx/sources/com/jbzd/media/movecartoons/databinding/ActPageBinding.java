package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.PageRefreshLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActPageBinding implements ViewBinding {

    @NonNull
    public final AppCompatButton btnChoiceModel;

    @NonNull
    public final RecyclerView list;

    @NonNull
    public final ConstraintLayout listToggleModel;

    @NonNull
    public final PageRefreshLayout pager;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final CheckBox toggleChoiceModel;

    private ActPageBinding(@NonNull FrameLayout frameLayout, @NonNull AppCompatButton appCompatButton, @NonNull RecyclerView recyclerView, @NonNull ConstraintLayout constraintLayout, @NonNull PageRefreshLayout pageRefreshLayout, @NonNull CheckBox checkBox) {
        this.rootView = frameLayout;
        this.btnChoiceModel = appCompatButton;
        this.list = recyclerView;
        this.listToggleModel = constraintLayout;
        this.pager = pageRefreshLayout;
        this.toggleChoiceModel = checkBox;
    }

    @NonNull
    public static ActPageBinding bind(@NonNull View view) {
        int i2 = R.id.btn_choice_model;
        AppCompatButton appCompatButton = (AppCompatButton) view.findViewById(R.id.btn_choice_model);
        if (appCompatButton != null) {
            i2 = R.id.list;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.list);
            if (recyclerView != null) {
                i2 = R.id.list_toggle_model;
                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.list_toggle_model);
                if (constraintLayout != null) {
                    i2 = R.id.pager;
                    PageRefreshLayout pageRefreshLayout = (PageRefreshLayout) view.findViewById(R.id.pager);
                    if (pageRefreshLayout != null) {
                        i2 = R.id.toggle_choice_model;
                        CheckBox checkBox = (CheckBox) view.findViewById(R.id.toggle_choice_model);
                        if (checkBox != null) {
                            return new ActPageBinding((FrameLayout) view, appCompatButton, recyclerView, constraintLayout, pageRefreshLayout, checkBox);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActPageBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPageBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_page, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
