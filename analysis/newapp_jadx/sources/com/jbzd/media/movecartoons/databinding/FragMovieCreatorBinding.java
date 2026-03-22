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
public final class FragMovieCreatorBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final LinearLayout llHead;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvBuyFansBtn;

    @NonNull
    public final TextView tvDoCollectForce;

    @NonNull
    public final TextView tvPostdetailNickname;

    @NonNull
    public final TextView tvUserDesc;

    private FragMovieCreatorBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull LinearLayout linearLayout2, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.llHead = linearLayout2;
        this.tvBuyFansBtn = textView;
        this.tvDoCollectForce = textView2;
        this.tvPostdetailNickname = textView3;
        this.tvUserDesc = textView4;
    }

    @NonNull
    public static FragMovieCreatorBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.ll_head;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_head);
            if (linearLayout != null) {
                i2 = R.id.tv_buyFansBtn;
                TextView textView = (TextView) view.findViewById(R.id.tv_buyFansBtn);
                if (textView != null) {
                    i2 = R.id.tv_doCollect_force;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_doCollect_force);
                    if (textView2 != null) {
                        i2 = R.id.tv_postdetail_nickname;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                        if (textView3 != null) {
                            i2 = R.id.tv_userDesc;
                            TextView textView4 = (TextView) view.findViewById(R.id.tv_userDesc);
                            if (textView4 != null) {
                                return new FragMovieCreatorBinding((LinearLayout) view, circleImageView, linearLayout, textView, textView2, textView3, textView4);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragMovieCreatorBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragMovieCreatorBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_movie_creator, viewGroup, false);
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
