package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemHomeTagBinding implements ViewBinding {

    @NonNull
    public final ImageView ivDel;

    @NonNull
    public final LinearLayout llParent;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvName;

    private ItemHomeTagBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.ivDel = imageView;
        this.llParent = linearLayout2;
        this.tvName = textView;
    }

    @NonNull
    public static ItemHomeTagBinding bind(@NonNull View view) {
        int i2 = R.id.iv_del;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_del);
        if (imageView != null) {
            i2 = R.id.ll_parent;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_parent);
            if (linearLayout != null) {
                i2 = R.id.tv_name;
                TextView textView = (TextView) view.findViewById(R.id.tv_name);
                if (textView != null) {
                    return new ItemHomeTagBinding((LinearLayout) view, imageView, linearLayout, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemHomeTagBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemHomeTagBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_home_tag, viewGroup, false);
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
