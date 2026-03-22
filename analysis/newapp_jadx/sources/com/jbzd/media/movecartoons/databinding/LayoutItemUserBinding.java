package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.CustomUserView;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LayoutItemUserBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvMicrotanotWantsee;

    @NonNull
    public final FollowTextView itvPostuserFollow;

    @NonNull
    public final ImageView ivCreaterType;

    @NonNull
    public final ImageView ivPostitemUper;

    @NonNull
    public final ImageView ivPostitemUservip;

    @NonNull
    public final CircleImageView ivUserfollowAvatar;

    @NonNull
    public final LinearLayout llPosthomeUsertop;

    @NonNull
    public final CustomUserView profile;

    @NonNull
    public final RelativeLayout rlWantsee;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvPostCreatedAt;

    @NonNull
    public final TextView tvPostdetailNickname;

    private LayoutItemUserBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull FollowTextView followTextView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull CircleImageView circleImageView, @NonNull LinearLayout linearLayout2, @NonNull CustomUserView customUserView, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.itvMicrotanotWantsee = imageTextView;
        this.itvPostuserFollow = followTextView;
        this.ivCreaterType = imageView;
        this.ivPostitemUper = imageView2;
        this.ivPostitemUservip = imageView3;
        this.ivUserfollowAvatar = circleImageView;
        this.llPosthomeUsertop = linearLayout2;
        this.profile = customUserView;
        this.rlWantsee = relativeLayout;
        this.tvPostCreatedAt = textView;
        this.tvPostdetailNickname = textView2;
    }

    @NonNull
    public static LayoutItemUserBinding bind(@NonNull View view) {
        int i2 = R.id.itv_microtanot_wantsee;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_microtanot_wantsee);
        if (imageTextView != null) {
            i2 = R.id.itv_postuser_follow;
            FollowTextView followTextView = (FollowTextView) view.findViewById(R.id.itv_postuser_follow);
            if (followTextView != null) {
                i2 = R.id.iv_creater_type;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_creater_type);
                if (imageView != null) {
                    i2 = R.id.iv_postitem_uper;
                    ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_postitem_uper);
                    if (imageView2 != null) {
                        i2 = R.id.iv_postitem_uservip;
                        ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_postitem_uservip);
                        if (imageView3 != null) {
                            i2 = R.id.iv_userfollow_avatar;
                            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_userfollow_avatar);
                            if (circleImageView != null) {
                                LinearLayout linearLayout = (LinearLayout) view;
                                i2 = R.id.profile;
                                CustomUserView customUserView = (CustomUserView) view.findViewById(R.id.profile);
                                if (customUserView != null) {
                                    i2 = R.id.rl_wantsee;
                                    RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_wantsee);
                                    if (relativeLayout != null) {
                                        i2 = R.id.tv_post_created_at;
                                        TextView textView = (TextView) view.findViewById(R.id.tv_post_created_at);
                                        if (textView != null) {
                                            i2 = R.id.tv_postdetail_nickname;
                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                                            if (textView2 != null) {
                                                return new LayoutItemUserBinding(linearLayout, imageTextView, followTextView, imageView, imageView2, imageView3, circleImageView, linearLayout, customUserView, relativeLayout, textView, textView2);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutItemUserBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutItemUserBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_item_user, viewGroup, false);
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
