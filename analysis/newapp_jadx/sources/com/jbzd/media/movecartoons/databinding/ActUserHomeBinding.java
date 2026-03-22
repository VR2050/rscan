package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActUserHomeBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final TextView fans;

    @NonNull
    public final TextView follows;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final ImageView ivType;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView totalTrade;

    @NonNull
    public final TextView tvLove;

    @NonNull
    public final TextView tvPostdetailNickname;

    @NonNull
    public final ImageView userBgTop;

    private ActUserHomeBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull ImageView imageView2) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.fans = textView;
        this.follows = textView2;
        this.fragContent = frameLayout;
        this.ivType = imageView;
        this.totalTrade = textView3;
        this.tvLove = textView4;
        this.tvPostdetailNickname = textView5;
        this.userBgTop = imageView2;
    }

    @NonNull
    public static ActUserHomeBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.fans;
            TextView textView = (TextView) view.findViewById(R.id.fans);
            if (textView != null) {
                i2 = R.id.follows;
                TextView textView2 = (TextView) view.findViewById(R.id.follows);
                if (textView2 != null) {
                    i2 = R.id.frag_content;
                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
                    if (frameLayout != null) {
                        i2 = R.id.ivType;
                        ImageView imageView = (ImageView) view.findViewById(R.id.ivType);
                        if (imageView != null) {
                            i2 = R.id.total_trade;
                            TextView textView3 = (TextView) view.findViewById(R.id.total_trade);
                            if (textView3 != null) {
                                i2 = R.id.tvLove;
                                TextView textView4 = (TextView) view.findViewById(R.id.tvLove);
                                if (textView4 != null) {
                                    i2 = R.id.tv_postdetail_nickname;
                                    TextView textView5 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                                    if (textView5 != null) {
                                        i2 = R.id.user_bg_top;
                                        ImageView imageView2 = (ImageView) view.findViewById(R.id.user_bg_top);
                                        if (imageView2 != null) {
                                            return new ActUserHomeBinding((LinearLayout) view, circleImageView, textView, textView2, frameLayout, imageView, textView3, textView4, textView5, imageView2);
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
    public static ActUserHomeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActUserHomeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_user_home, viewGroup, false);
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
