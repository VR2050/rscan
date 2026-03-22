package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemMovieDetailSerialsBinding implements ViewBinding {

    @NonNull
    public final MyRadioButton btnMovieSerials;

    @NonNull
    private final ConstraintLayout rootView;

    private ItemMovieDetailSerialsBinding(@NonNull ConstraintLayout constraintLayout, @NonNull MyRadioButton myRadioButton) {
        this.rootView = constraintLayout;
        this.btnMovieSerials = myRadioButton;
    }

    @NonNull
    public static ItemMovieDetailSerialsBinding bind(@NonNull View view) {
        MyRadioButton myRadioButton = (MyRadioButton) view.findViewById(R.id.btn_movie_serials);
        if (myRadioButton != null) {
            return new ItemMovieDetailSerialsBinding((ConstraintLayout) view, myRadioButton);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.btn_movie_serials)));
    }

    @NonNull
    public static ItemMovieDetailSerialsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemMovieDetailSerialsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_movie_detail_serials, viewGroup, false);
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
