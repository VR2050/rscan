package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.widget.NestedScrollView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActAccountCardidBinding implements ViewBinding {

    @NonNull
    public final TextView btnSaveCardid;

    @NonNull
    public final ImageView ivLogo;

    @NonNull
    public final ShapeableImageView ivQrcodeCardid;

    @NonNull
    public final ConstraintLayout llCardInfo;

    @NonNull
    private final NestedScrollView rootView;

    @NonNull
    public final TextView tvAccountCard;

    @NonNull
    public final TextView tvAccountInfo;

    @NonNull
    public final TextView tvAccountNotice;

    @NonNull
    public final TextView tvAppname;

    @NonNull
    public final TextView tvCodeTag;

    @NonNull
    public final TextView tvFoundNoticTips;

    @NonNull
    public final TextView tvIdTag;

    @NonNull
    public final TextView tvInviteCode;

    @NonNull
    public final TextView tvNickName;

    @NonNull
    public final TextView tvNickTag;

    @NonNull
    public final TextView tvNotice;

    @NonNull
    public final TextView tvSiteUrl;

    @NonNull
    public final TextView tvUseMethod;

    @NonNull
    public final TextView tvUseTips;

    @NonNull
    public final TextView tvUserId;

    private ActAccountCardidBinding(@NonNull NestedScrollView nestedScrollView, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull ConstraintLayout constraintLayout, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10, @NonNull TextView textView11, @NonNull TextView textView12, @NonNull TextView textView13, @NonNull TextView textView14, @NonNull TextView textView15, @NonNull TextView textView16) {
        this.rootView = nestedScrollView;
        this.btnSaveCardid = textView;
        this.ivLogo = imageView;
        this.ivQrcodeCardid = shapeableImageView;
        this.llCardInfo = constraintLayout;
        this.tvAccountCard = textView2;
        this.tvAccountInfo = textView3;
        this.tvAccountNotice = textView4;
        this.tvAppname = textView5;
        this.tvCodeTag = textView6;
        this.tvFoundNoticTips = textView7;
        this.tvIdTag = textView8;
        this.tvInviteCode = textView9;
        this.tvNickName = textView10;
        this.tvNickTag = textView11;
        this.tvNotice = textView12;
        this.tvSiteUrl = textView13;
        this.tvUseMethod = textView14;
        this.tvUseTips = textView15;
        this.tvUserId = textView16;
    }

    @NonNull
    public static ActAccountCardidBinding bind(@NonNull View view) {
        int i2 = R.id.btn_save_cardid;
        TextView textView = (TextView) view.findViewById(R.id.btn_save_cardid);
        if (textView != null) {
            i2 = R.id.iv_logo;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_logo);
            if (imageView != null) {
                i2 = R.id.iv_qrcode_cardid;
                ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_qrcode_cardid);
                if (shapeableImageView != null) {
                    i2 = R.id.ll_card_info;
                    ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.ll_card_info);
                    if (constraintLayout != null) {
                        i2 = R.id.tv_account_card;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_account_card);
                        if (textView2 != null) {
                            i2 = R.id.tv_account_info;
                            TextView textView3 = (TextView) view.findViewById(R.id.tv_account_info);
                            if (textView3 != null) {
                                i2 = R.id.tv_account_notice;
                                TextView textView4 = (TextView) view.findViewById(R.id.tv_account_notice);
                                if (textView4 != null) {
                                    i2 = R.id.tv_appname;
                                    TextView textView5 = (TextView) view.findViewById(R.id.tv_appname);
                                    if (textView5 != null) {
                                        i2 = R.id.tv_code_tag;
                                        TextView textView6 = (TextView) view.findViewById(R.id.tv_code_tag);
                                        if (textView6 != null) {
                                            i2 = R.id.tv_found_notic_tips;
                                            TextView textView7 = (TextView) view.findViewById(R.id.tv_found_notic_tips);
                                            if (textView7 != null) {
                                                i2 = R.id.tv_id_tag;
                                                TextView textView8 = (TextView) view.findViewById(R.id.tv_id_tag);
                                                if (textView8 != null) {
                                                    i2 = R.id.tv_invite_code;
                                                    TextView textView9 = (TextView) view.findViewById(R.id.tv_invite_code);
                                                    if (textView9 != null) {
                                                        i2 = R.id.tv_nick_name;
                                                        TextView textView10 = (TextView) view.findViewById(R.id.tv_nick_name);
                                                        if (textView10 != null) {
                                                            i2 = R.id.tv_nick_tag;
                                                            TextView textView11 = (TextView) view.findViewById(R.id.tv_nick_tag);
                                                            if (textView11 != null) {
                                                                i2 = R.id.tv_notice;
                                                                TextView textView12 = (TextView) view.findViewById(R.id.tv_notice);
                                                                if (textView12 != null) {
                                                                    i2 = R.id.tv_site_url;
                                                                    TextView textView13 = (TextView) view.findViewById(R.id.tv_site_url);
                                                                    if (textView13 != null) {
                                                                        i2 = R.id.tv_use_method;
                                                                        TextView textView14 = (TextView) view.findViewById(R.id.tv_use_method);
                                                                        if (textView14 != null) {
                                                                            i2 = R.id.tv_use_tips;
                                                                            TextView textView15 = (TextView) view.findViewById(R.id.tv_use_tips);
                                                                            if (textView15 != null) {
                                                                                i2 = R.id.tv_user_id;
                                                                                TextView textView16 = (TextView) view.findViewById(R.id.tv_user_id);
                                                                                if (textView16 != null) {
                                                                                    return new ActAccountCardidBinding((NestedScrollView) view, textView, imageView, shapeableImageView, constraintLayout, textView2, textView3, textView4, textView5, textView6, textView7, textView8, textView9, textView10, textView11, textView12, textView13, textView14, textView15, textView16);
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
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActAccountCardidBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActAccountCardidBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_account_cardid, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public NestedScrollView getRoot() {
        return this.rootView;
    }
}
