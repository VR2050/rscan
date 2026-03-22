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
import androidx.cardview.widget.CardView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPosttopicBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvMicrotanotWantsee;

    @NonNull
    public final CircleImageView ivPosttopicLeftAvatar;

    @NonNull
    public final ImageView ivSelect;

    @NonNull
    public final LinearLayout llMicrotanotUserrow;

    @NonNull
    public final RelativeLayout rlWantsee;

    @NonNull
    private final CardView rootView;

    @NonNull
    public final TextView tvPostTopticsFollowers;

    @NonNull
    public final TextView tvPostTopticsNumber;

    @NonNull
    public final TextView tvPostTopticsTimes;

    @NonNull
    public final TextView tvPosttopicName;

    private ItemPosttopicBinding(@NonNull CardView cardView, @NonNull ImageTextView imageTextView, @NonNull CircleImageView circleImageView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = cardView;
        this.itvMicrotanotWantsee = imageTextView;
        this.ivPosttopicLeftAvatar = circleImageView;
        this.ivSelect = imageView;
        this.llMicrotanotUserrow = linearLayout;
        this.rlWantsee = relativeLayout;
        this.tvPostTopticsFollowers = textView;
        this.tvPostTopticsNumber = textView2;
        this.tvPostTopticsTimes = textView3;
        this.tvPosttopicName = textView4;
    }

    @NonNull
    public static ItemPosttopicBinding bind(@NonNull View view) {
        int i2 = R.id.itv_microtanot_wantsee;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_microtanot_wantsee);
        if (imageTextView != null) {
            i2 = R.id.iv_posttopic_left_avatar;
            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_posttopic_left_avatar);
            if (circleImageView != null) {
                i2 = R.id.iv_select;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_select);
                if (imageView != null) {
                    i2 = R.id.ll_microtanot_userrow;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_microtanot_userrow);
                    if (linearLayout != null) {
                        i2 = R.id.rl_wantsee;
                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_wantsee);
                        if (relativeLayout != null) {
                            i2 = R.id.tv_post_toptics_followers;
                            TextView textView = (TextView) view.findViewById(R.id.tv_post_toptics_followers);
                            if (textView != null) {
                                i2 = R.id.tv_post_toptics_number;
                                TextView textView2 = (TextView) view.findViewById(R.id.tv_post_toptics_number);
                                if (textView2 != null) {
                                    i2 = R.id.tv_post_toptics_times;
                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_post_toptics_times);
                                    if (textView3 != null) {
                                        i2 = R.id.tv_posttopic_name;
                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_posttopic_name);
                                        if (textView4 != null) {
                                            return new ItemPosttopicBinding((CardView) view, imageTextView, circleImageView, imageView, linearLayout, relativeLayout, textView, textView2, textView3, textView4);
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
    public static ItemPosttopicBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPosttopicBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_posttopic, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public CardView getRoot() {
        return this.rootView;
    }
}
