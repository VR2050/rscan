package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogMultilinksChooseBinding implements ViewBinding {

    @NonNull
    public final ImageView ivDismiss;

    @NonNull
    public final View outsideView;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvMultilinksDialog;

    private DialogMultilinksChooseBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull View view, @NonNull RecyclerView recyclerView) {
        this.rootView = linearLayout;
        this.ivDismiss = imageView;
        this.outsideView = view;
        this.rvMultilinksDialog = recyclerView;
    }

    @NonNull
    public static DialogMultilinksChooseBinding bind(@NonNull View view) {
        int i2 = R.id.iv_dismiss;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_dismiss);
        if (imageView != null) {
            i2 = R.id.outside_view;
            View findViewById = view.findViewById(R.id.outside_view);
            if (findViewById != null) {
                i2 = R.id.rv_multilinks_dialog;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_multilinks_dialog);
                if (recyclerView != null) {
                    return new DialogMultilinksChooseBinding((LinearLayout) view, imageView, findViewById, recyclerView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogMultilinksChooseBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogMultilinksChooseBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_multilinks_choose, viewGroup, false);
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
