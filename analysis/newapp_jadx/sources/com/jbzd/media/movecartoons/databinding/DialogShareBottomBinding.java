package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogShareBottomBinding implements ViewBinding {

    @NonNull
    public final ImageView ivDismiss;

    @NonNull
    public final View outsideView;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvLinks;

    @NonNull
    public final TextView tvShareRule;

    private DialogShareBottomBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull View view, @NonNull RecyclerView recyclerView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.ivDismiss = imageView;
        this.outsideView = view;
        this.rvLinks = recyclerView;
        this.tvShareRule = textView;
    }

    @NonNull
    public static DialogShareBottomBinding bind(@NonNull View view) {
        int i2 = R.id.iv_dismiss;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_dismiss);
        if (imageView != null) {
            i2 = R.id.outside_view;
            View findViewById = view.findViewById(R.id.outside_view);
            if (findViewById != null) {
                i2 = R.id.rv_links;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_links);
                if (recyclerView != null) {
                    i2 = R.id.tv_shareRule;
                    TextView textView = (TextView) view.findViewById(R.id.tv_shareRule);
                    if (textView != null) {
                        return new DialogShareBottomBinding((LinearLayout) view, imageView, findViewById, recyclerView, textView);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogShareBottomBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogShareBottomBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_share_bottom, viewGroup, false);
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
