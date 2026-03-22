package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.XRefreshLayout;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragChangeScoreBinding implements ViewBinding {

    @NonNull
    public final ImageView ivDiamondBg;

    @NonNull
    public final CircleImageView ivUserAvatarScore;

    @NonNull
    public final XRefreshLayout refreshLayoutChangestore;

    @NonNull
    private final XRefreshLayout rootView;

    @NonNull
    public final RecyclerView rvGroup;

    @NonNull
    public final TextView tvMyDiamond;

    @NonNull
    public final TextView tvRoleScoreName;

    @NonNull
    public final TextView tvScoreCurrent;

    @NonNull
    public final TextView tvWatchNum;

    @NonNull
    public final TextView walletPoint;

    private FragChangeScoreBinding(@NonNull XRefreshLayout xRefreshLayout, @NonNull ImageView imageView, @NonNull CircleImageView circleImageView, @NonNull XRefreshLayout xRefreshLayout2, @NonNull RecyclerView recyclerView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = xRefreshLayout;
        this.ivDiamondBg = imageView;
        this.ivUserAvatarScore = circleImageView;
        this.refreshLayoutChangestore = xRefreshLayout2;
        this.rvGroup = recyclerView;
        this.tvMyDiamond = textView;
        this.tvRoleScoreName = textView2;
        this.tvScoreCurrent = textView3;
        this.tvWatchNum = textView4;
        this.walletPoint = textView5;
    }

    @NonNull
    public static FragChangeScoreBinding bind(@NonNull View view) {
        int i2 = R.id.ivDiamondBg;
        ImageView imageView = (ImageView) view.findViewById(R.id.ivDiamondBg);
        if (imageView != null) {
            i2 = R.id.iv_user_avatar_score;
            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_user_avatar_score);
            if (circleImageView != null) {
                XRefreshLayout xRefreshLayout = (XRefreshLayout) view;
                i2 = R.id.rv_group;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_group);
                if (recyclerView != null) {
                    i2 = R.id.tvMyDiamond;
                    TextView textView = (TextView) view.findViewById(R.id.tvMyDiamond);
                    if (textView != null) {
                        i2 = R.id.tv_role_score_name;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_role_score_name);
                        if (textView2 != null) {
                            i2 = R.id.tv_score_current;
                            TextView textView3 = (TextView) view.findViewById(R.id.tv_score_current);
                            if (textView3 != null) {
                                i2 = R.id.tv_watch_num;
                                TextView textView4 = (TextView) view.findViewById(R.id.tv_watch_num);
                                if (textView4 != null) {
                                    i2 = R.id.wallet_point;
                                    TextView textView5 = (TextView) view.findViewById(R.id.wallet_point);
                                    if (textView5 != null) {
                                        return new FragChangeScoreBinding(xRefreshLayout, imageView, circleImageView, xRefreshLayout, recyclerView, textView, textView2, textView3, textView4, textView5);
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
    public static FragChangeScoreBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragChangeScoreBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_change_score, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public XRefreshLayout getRoot() {
        return this.rootView;
    }
}
