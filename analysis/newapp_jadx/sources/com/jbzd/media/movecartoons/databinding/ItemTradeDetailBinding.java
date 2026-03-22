package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.jbzd.media.movecartoons.view.SquareGridView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemTradeDetailBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnSubmitAichangefaceVideo;

    @NonNull
    public final ConstraintLayout clTradeDetail;

    @NonNull
    public final TextView etvContent;

    @NonNull
    public final FrameLayout flCover;

    @NonNull
    public final ImageView ivMineAvatar;

    @NonNull
    public final ImageView ivVideoCover;

    @NonNull
    public final ImageView ivVip;

    @NonNull
    public final RelativeLayout rlItemVideo;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final SquareGridView squareGridImages;

    @NonNull
    public final TextView tvDeposit;

    @NonNull
    public final ImageTextView tvExpand;

    @NonNull
    public final TextView tvPostdetailNickname;

    @NonNull
    public final TextView tvType;

    private ItemTradeDetailBinding(@NonNull ConstraintLayout constraintLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull ConstraintLayout constraintLayout2, @NonNull TextView textView, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull RelativeLayout relativeLayout, @NonNull RecyclerView recyclerView, @NonNull SquareGridView squareGridView, @NonNull TextView textView2, @NonNull ImageTextView imageTextView, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = constraintLayout;
        this.btnSubmitAichangefaceVideo = gradientRoundCornerButton;
        this.clTradeDetail = constraintLayout2;
        this.etvContent = textView;
        this.flCover = frameLayout;
        this.ivMineAvatar = imageView;
        this.ivVideoCover = imageView2;
        this.ivVip = imageView3;
        this.rlItemVideo = relativeLayout;
        this.rvTag = recyclerView;
        this.squareGridImages = squareGridView;
        this.tvDeposit = textView2;
        this.tvExpand = imageTextView;
        this.tvPostdetailNickname = textView3;
        this.tvType = textView4;
    }

    @NonNull
    public static ItemTradeDetailBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aichangeface_video;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn_submit_aichangeface_video);
        if (gradientRoundCornerButton != null) {
            ConstraintLayout constraintLayout = (ConstraintLayout) view;
            i2 = R.id.etv_content;
            TextView textView = (TextView) view.findViewById(R.id.etv_content);
            if (textView != null) {
                i2 = R.id.fl_cover;
                FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.fl_cover);
                if (frameLayout != null) {
                    i2 = R.id.iv_mine_avatar;
                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_mine_avatar);
                    if (imageView != null) {
                        i2 = R.id.iv_video_cover;
                        ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_video_cover);
                        if (imageView2 != null) {
                            i2 = R.id.iv_vip;
                            ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_vip);
                            if (imageView3 != null) {
                                i2 = R.id.rl_item_video;
                                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_item_video);
                                if (relativeLayout != null) {
                                    i2 = R.id.rv_tag;
                                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_tag);
                                    if (recyclerView != null) {
                                        i2 = R.id.square_grid_images;
                                        SquareGridView squareGridView = (SquareGridView) view.findViewById(R.id.square_grid_images);
                                        if (squareGridView != null) {
                                            i2 = R.id.tv_deposit;
                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_deposit);
                                            if (textView2 != null) {
                                                i2 = R.id.tv_expand;
                                                ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.tv_expand);
                                                if (imageTextView != null) {
                                                    i2 = R.id.tv_postdetail_nickname;
                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                                                    if (textView3 != null) {
                                                        i2 = R.id.tv_type;
                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_type);
                                                        if (textView4 != null) {
                                                            return new ItemTradeDetailBinding(constraintLayout, gradientRoundCornerButton, constraintLayout, textView, frameLayout, imageView, imageView2, imageView3, relativeLayout, recyclerView, squareGridView, textView2, imageTextView, textView3, textView4);
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
    public static ItemTradeDetailBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemTradeDetailBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_trade_detail, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
