package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemCreatorHorBinding implements ViewBinding {

    @NonNull
    public final CircleImageView ivHead;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvDoFollow;

    @NonNull
    public final TextView tvName;

    private ItemCreatorHorBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.ivHead = circleImageView;
        this.tvDesc = textView;
        this.tvDoFollow = textView2;
        this.tvName = textView3;
    }

    @NonNull
    public static ItemCreatorHorBinding bind(@NonNull View view) {
        int i2 = R.id.iv_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_head);
        if (circleImageView != null) {
            i2 = R.id.tv_desc;
            TextView textView = (TextView) view.findViewById(R.id.tv_desc);
            if (textView != null) {
                i2 = R.id.tv_doFollow;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_doFollow);
                if (textView2 != null) {
                    i2 = R.id.tv_name;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_name);
                    if (textView3 != null) {
                        return new ItemCreatorHorBinding((LinearLayout) view, circleImageView, textView, textView2, textView3);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemCreatorHorBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemCreatorHorBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_creator_hor, viewGroup, false);
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
