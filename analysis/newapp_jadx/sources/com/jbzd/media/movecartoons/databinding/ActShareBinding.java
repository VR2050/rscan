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
import androidx.appcompat.widget.AppCompatButton;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActShareBinding implements ViewBinding {

    @NonNull
    public final AppCompatButton btnCopyLink;

    @NonNull
    public final AppCompatButton btnSaveImage;

    @NonNull
    public final ImageView iconHeader;

    @NonNull
    public final TextView imgTips;

    @NonNull
    public final ImageView ivCode;

    @NonNull
    public final ShapeableImageView ivIconLogo;

    @NonNull
    public final ConstraintLayout layoutInviteHeader;

    @NonNull
    public final FrameLayout llTopInvite;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvAppName;

    @NonNull
    public final TextView tvAppNameTips;

    @NonNull
    public final TextView tvCode;

    @NonNull
    public final TextView txtInviteDay;

    @NonNull
    public final TextView txtShareUrl;

    @NonNull
    public final TextView txtTipsContent;

    @NonNull
    public final TextView txtWebLabel;

    private ActShareBinding(@NonNull LinearLayout linearLayout, @NonNull AppCompatButton appCompatButton, @NonNull AppCompatButton appCompatButton2, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull ImageView imageView2, @NonNull ShapeableImageView shapeableImageView, @NonNull ConstraintLayout constraintLayout, @NonNull FrameLayout frameLayout, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8) {
        this.rootView = linearLayout;
        this.btnCopyLink = appCompatButton;
        this.btnSaveImage = appCompatButton2;
        this.iconHeader = imageView;
        this.imgTips = textView;
        this.ivCode = imageView2;
        this.ivIconLogo = shapeableImageView;
        this.layoutInviteHeader = constraintLayout;
        this.llTopInvite = frameLayout;
        this.tvAppName = textView2;
        this.tvAppNameTips = textView3;
        this.tvCode = textView4;
        this.txtInviteDay = textView5;
        this.txtShareUrl = textView6;
        this.txtTipsContent = textView7;
        this.txtWebLabel = textView8;
    }

    @NonNull
    public static ActShareBinding bind(@NonNull View view) {
        int i2 = R.id.btn_copy_link;
        AppCompatButton appCompatButton = (AppCompatButton) view.findViewById(R.id.btn_copy_link);
        if (appCompatButton != null) {
            i2 = R.id.btn_save_image;
            AppCompatButton appCompatButton2 = (AppCompatButton) view.findViewById(R.id.btn_save_image);
            if (appCompatButton2 != null) {
                i2 = R.id.icon_header;
                ImageView imageView = (ImageView) view.findViewById(R.id.icon_header);
                if (imageView != null) {
                    i2 = R.id.img_tips;
                    TextView textView = (TextView) view.findViewById(R.id.img_tips);
                    if (textView != null) {
                        i2 = R.id.iv_code;
                        ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_code);
                        if (imageView2 != null) {
                            i2 = R.id.iv_icon_logo;
                            ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_icon_logo);
                            if (shapeableImageView != null) {
                                i2 = R.id.layout_invite_header;
                                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.layout_invite_header);
                                if (constraintLayout != null) {
                                    i2 = R.id.ll_top_invite;
                                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.ll_top_invite);
                                    if (frameLayout != null) {
                                        i2 = R.id.tv_app_name;
                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_app_name);
                                        if (textView2 != null) {
                                            i2 = R.id.tv_app_name_tips;
                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_app_name_tips);
                                            if (textView3 != null) {
                                                i2 = R.id.tv_code;
                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_code);
                                                if (textView4 != null) {
                                                    i2 = R.id.txt_invite_day;
                                                    TextView textView5 = (TextView) view.findViewById(R.id.txt_invite_day);
                                                    if (textView5 != null) {
                                                        i2 = R.id.txt_share_url;
                                                        TextView textView6 = (TextView) view.findViewById(R.id.txt_share_url);
                                                        if (textView6 != null) {
                                                            i2 = R.id.txt_tips_content;
                                                            TextView textView7 = (TextView) view.findViewById(R.id.txt_tips_content);
                                                            if (textView7 != null) {
                                                                i2 = R.id.txt_web_label;
                                                                TextView textView8 = (TextView) view.findViewById(R.id.txt_web_label);
                                                                if (textView8 != null) {
                                                                    return new ActShareBinding((LinearLayout) view, appCompatButton, appCompatButton2, imageView, textView, imageView2, shapeableImageView, constraintLayout, frameLayout, textView2, textView3, textView4, textView5, textView6, textView7, textView8);
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
    public static ActShareBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActShareBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_share, viewGroup, false);
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
