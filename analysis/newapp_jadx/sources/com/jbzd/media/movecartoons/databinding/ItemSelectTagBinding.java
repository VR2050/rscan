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
public final class ItemSelectTagBinding implements ViewBinding {

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    public final ImageView ivSelect;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvPost;

    private ItemSelectTagBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.ivCenterPlayicon = textView;
        this.ivSelect = imageView;
        this.tvPost = textView2;
    }

    @NonNull
    public static ItemSelectTagBinding bind(@NonNull View view) {
        int i2 = R.id.iv_center_playicon;
        TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
        if (textView != null) {
            i2 = R.id.ivSelect;
            ImageView imageView = (ImageView) view.findViewById(R.id.ivSelect);
            if (imageView != null) {
                i2 = R.id.tvPost;
                TextView textView2 = (TextView) view.findViewById(R.id.tvPost);
                if (textView2 != null) {
                    return new ItemSelectTagBinding((LinearLayout) view, textView, imageView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemSelectTagBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSelectTagBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_select_tag, viewGroup, false);
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
