package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.XRefreshLayout;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragmentExchangeBinding implements ViewBinding {

    @NonNull
    public final CircleImageView ivUserAvatar;

    @NonNull
    public final ConstraintLayout llSignedDay;

    @NonNull
    public final XRefreshLayout refreshLayoutFltask;

    @NonNull
    private final XRefreshLayout rootView;

    @NonNull
    public final RecyclerView rvSigned;

    @NonNull
    public final RecyclerView rvTask;

    @NonNull
    public final BLTextView tvChangeVip;

    @NonNull
    public final TextView tvCoin;

    @NonNull
    public final TextView tvInvitedCount;

    @NonNull
    public final TextView tvRole;

    @NonNull
    public final TextView tvScoreUserCurrent;

    @NonNull
    public final TextView tvSignNow;

    @NonNull
    public final TextView tvSignedDay;

    @NonNull
    public final TextView tvTaskText;

    @NonNull
    public final TextView tvTipText;

    private FragmentExchangeBinding(@NonNull XRefreshLayout xRefreshLayout, @NonNull CircleImageView circleImageView, @NonNull ConstraintLayout constraintLayout, @NonNull XRefreshLayout xRefreshLayout2, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull BLTextView bLTextView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8) {
        this.rootView = xRefreshLayout;
        this.ivUserAvatar = circleImageView;
        this.llSignedDay = constraintLayout;
        this.refreshLayoutFltask = xRefreshLayout2;
        this.rvSigned = recyclerView;
        this.rvTask = recyclerView2;
        this.tvChangeVip = bLTextView;
        this.tvCoin = textView;
        this.tvInvitedCount = textView2;
        this.tvRole = textView3;
        this.tvScoreUserCurrent = textView4;
        this.tvSignNow = textView5;
        this.tvSignedDay = textView6;
        this.tvTaskText = textView7;
        this.tvTipText = textView8;
    }

    @NonNull
    public static FragmentExchangeBinding bind(@NonNull View view) {
        int i2 = R.id.iv_user_avatar;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_user_avatar);
        if (circleImageView != null) {
            i2 = R.id.ll_signed_day;
            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.ll_signed_day);
            if (constraintLayout != null) {
                XRefreshLayout xRefreshLayout = (XRefreshLayout) view;
                i2 = R.id.rv_signed;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_signed);
                if (recyclerView != null) {
                    i2 = R.id.rv_task;
                    RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_task);
                    if (recyclerView2 != null) {
                        i2 = R.id.tv_change_vip;
                        BLTextView bLTextView = (BLTextView) view.findViewById(R.id.tv_change_vip);
                        if (bLTextView != null) {
                            i2 = R.id.tv_coin;
                            TextView textView = (TextView) view.findViewById(R.id.tv_coin);
                            if (textView != null) {
                                i2 = R.id.tv_invited_count;
                                TextView textView2 = (TextView) view.findViewById(R.id.tv_invited_count);
                                if (textView2 != null) {
                                    i2 = R.id.tv_role;
                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_role);
                                    if (textView3 != null) {
                                        i2 = R.id.tv_score_user_current;
                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_score_user_current);
                                        if (textView4 != null) {
                                            i2 = R.id.tv_sign_now;
                                            TextView textView5 = (TextView) view.findViewById(R.id.tv_sign_now);
                                            if (textView5 != null) {
                                                i2 = R.id.tv_signed_day;
                                                TextView textView6 = (TextView) view.findViewById(R.id.tv_signed_day);
                                                if (textView6 != null) {
                                                    i2 = R.id.tv_task_text;
                                                    TextView textView7 = (TextView) view.findViewById(R.id.tv_task_text);
                                                    if (textView7 != null) {
                                                        i2 = R.id.tv_tip_text;
                                                        TextView textView8 = (TextView) view.findViewById(R.id.tv_tip_text);
                                                        if (textView8 != null) {
                                                            return new FragmentExchangeBinding(xRefreshLayout, circleImageView, constraintLayout, xRefreshLayout, recyclerView, recyclerView2, bLTextView, textView, textView2, textView3, textView4, textView5, textView6, textView7, textView8);
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
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragmentExchangeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragmentExchangeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.fragment_exchange, viewGroup, false);
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
