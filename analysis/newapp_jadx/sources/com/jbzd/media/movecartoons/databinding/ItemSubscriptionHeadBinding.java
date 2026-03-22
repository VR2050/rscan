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
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemSubscriptionHeadBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final ImageView ivSubheaderVip;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvNickname;

    private ItemSubscriptionHeadBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull ImageView imageView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.ivSubheaderVip = imageView;
        this.tvNickname = textView;
    }

    @NonNull
    public static ItemSubscriptionHeadBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.iv_subheader_vip;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_subheader_vip);
            if (imageView != null) {
                i2 = R.id.tv_nickname;
                TextView textView = (TextView) view.findViewById(R.id.tv_nickname);
                if (textView != null) {
                    return new ItemSubscriptionHeadBinding((LinearLayout) view, circleImageView, imageView, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemSubscriptionHeadBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSubscriptionHeadBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_subscription_head, viewGroup, false);
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
