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
public final class ItemFollowUpperBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civAvatar;

    @NonNull
    public final TextView itvPostuserFollow;

    @NonNull
    public final ImageView ivSubheaderVip;

    @NonNull
    public final LinearLayout llFollowItem;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvFollowFans;

    @NonNull
    public final TextView tvFollowFollows;

    private ItemFollowUpperBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.civAvatar = circleImageView;
        this.itvPostuserFollow = textView;
        this.ivSubheaderVip = imageView;
        this.llFollowItem = linearLayout2;
        this.tvFollowFans = textView2;
        this.tvFollowFollows = textView3;
    }

    @NonNull
    public static ItemFollowUpperBinding bind(@NonNull View view) {
        int i2 = R.id.civ_avatar;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_avatar);
        if (circleImageView != null) {
            i2 = R.id.itv_postuser_follow;
            TextView textView = (TextView) view.findViewById(R.id.itv_postuser_follow);
            if (textView != null) {
                i2 = R.id.iv_subheader_vip;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_subheader_vip);
                if (imageView != null) {
                    LinearLayout linearLayout = (LinearLayout) view;
                    i2 = R.id.tv_follow_fans;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_follow_fans);
                    if (textView2 != null) {
                        i2 = R.id.tv_follow_follows;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_follow_follows);
                        if (textView3 != null) {
                            return new ItemFollowUpperBinding(linearLayout, circleImageView, textView, imageView, linearLayout, textView2, textView3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemFollowUpperBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemFollowUpperBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_follow_upper, viewGroup, false);
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
