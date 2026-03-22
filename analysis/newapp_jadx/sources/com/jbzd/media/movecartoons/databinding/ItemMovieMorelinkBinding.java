package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemMovieMorelinkBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llItemMultilink;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvMorelinkName;

    private ItemMovieMorelinkBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.llItemMultilink = linearLayout2;
        this.tvMorelinkName = textView;
    }

    @NonNull
    public static ItemMovieMorelinkBinding bind(@NonNull View view) {
        LinearLayout linearLayout = (LinearLayout) view;
        TextView textView = (TextView) view.findViewById(R.id.tv_morelink_name);
        if (textView != null) {
            return new ItemMovieMorelinkBinding((LinearLayout) view, linearLayout, textView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.tv_morelink_name)));
    }

    @NonNull
    public static ItemMovieMorelinkBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemMovieMorelinkBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_movie_morelink, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
