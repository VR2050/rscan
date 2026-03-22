package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.SquareGridView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemDarkTradeBinding implements ViewBinding {

    @NonNull
    public final FrameLayout flImg;

    @NonNull
    public final ImageTextView itvWatch;

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    public final ImageView ivHead;

    @NonNull
    public final ImageView ivType;

    @NonNull
    public final ImageView ivVideoCover;

    @NonNull
    public final LinearLayout llMoney;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final TextView reviewText;

    @NonNull
    public final RelativeLayout rlItemVideo;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final SquareGridView squareGridImages;

    @NonNull
    public final ImageView tvArrow;

    @NonNull
    public final TextView tvContent;

    @NonNull
    public final TextView tvDeal;

    @NonNull
    public final TextView tvDealStatus;

    @NonNull
    public final TextView tvIdentity;

    @NonNull
    public final TextView tvLove;

    @NonNull
    public final TextView tvMoney;

    @NonNull
    public final TextView tvSpinner;

    @NonNull
    public final TextView tvTime;

    private ItemDarkTradeBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull ImageTextView imageTextView, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull TextView textView2, @NonNull RelativeLayout relativeLayout, @NonNull RecyclerView recyclerView, @NonNull SquareGridView squareGridView, @NonNull ImageView imageView4, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10) {
        this.rootView = frameLayout;
        this.flImg = frameLayout2;
        this.itvWatch = imageTextView;
        this.ivCenterPlayicon = textView;
        this.ivHead = imageView;
        this.ivType = imageView2;
        this.ivVideoCover = imageView3;
        this.llMoney = linearLayout;
        this.llName = linearLayout2;
        this.reviewText = textView2;
        this.rlItemVideo = relativeLayout;
        this.rvTag = recyclerView;
        this.squareGridImages = squareGridView;
        this.tvArrow = imageView4;
        this.tvContent = textView3;
        this.tvDeal = textView4;
        this.tvDealStatus = textView5;
        this.tvIdentity = textView6;
        this.tvLove = textView7;
        this.tvMoney = textView8;
        this.tvSpinner = textView9;
        this.tvTime = textView10;
    }

    @NonNull
    public static ItemDarkTradeBinding bind(@NonNull View view) {
        int i2 = R.id.flImg;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.flImg);
        if (frameLayout != null) {
            i2 = R.id.itvWatch;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itvWatch);
            if (imageTextView != null) {
                i2 = R.id.iv_center_playicon;
                TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
                if (textView != null) {
                    i2 = R.id.ivHead;
                    ImageView imageView = (ImageView) view.findViewById(R.id.ivHead);
                    if (imageView != null) {
                        i2 = R.id.ivType;
                        ImageView imageView2 = (ImageView) view.findViewById(R.id.ivType);
                        if (imageView2 != null) {
                            i2 = R.id.iv_video_cover;
                            ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_video_cover);
                            if (imageView3 != null) {
                                i2 = R.id.llMoney;
                                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.llMoney);
                                if (linearLayout != null) {
                                    i2 = R.id.llName;
                                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.llName);
                                    if (linearLayout2 != null) {
                                        i2 = R.id.review_text;
                                        TextView textView2 = (TextView) view.findViewById(R.id.review_text);
                                        if (textView2 != null) {
                                            i2 = R.id.rl_item_video;
                                            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_item_video);
                                            if (relativeLayout != null) {
                                                i2 = R.id.rv_tag;
                                                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_tag);
                                                if (recyclerView != null) {
                                                    i2 = R.id.square_grid_images;
                                                    SquareGridView squareGridView = (SquareGridView) view.findViewById(R.id.square_grid_images);
                                                    if (squareGridView != null) {
                                                        i2 = R.id.tv_arrow;
                                                        ImageView imageView4 = (ImageView) view.findViewById(R.id.tv_arrow);
                                                        if (imageView4 != null) {
                                                            i2 = R.id.tvContent;
                                                            TextView textView3 = (TextView) view.findViewById(R.id.tvContent);
                                                            if (textView3 != null) {
                                                                i2 = R.id.tvDeal;
                                                                TextView textView4 = (TextView) view.findViewById(R.id.tvDeal);
                                                                if (textView4 != null) {
                                                                    i2 = R.id.tvDealStatus;
                                                                    TextView textView5 = (TextView) view.findViewById(R.id.tvDealStatus);
                                                                    if (textView5 != null) {
                                                                        i2 = R.id.tvIdentity;
                                                                        TextView textView6 = (TextView) view.findViewById(R.id.tvIdentity);
                                                                        if (textView6 != null) {
                                                                            i2 = R.id.tvLove;
                                                                            TextView textView7 = (TextView) view.findViewById(R.id.tvLove);
                                                                            if (textView7 != null) {
                                                                                i2 = R.id.tvMoney;
                                                                                TextView textView8 = (TextView) view.findViewById(R.id.tvMoney);
                                                                                if (textView8 != null) {
                                                                                    i2 = R.id.tv_spinner;
                                                                                    TextView textView9 = (TextView) view.findViewById(R.id.tv_spinner);
                                                                                    if (textView9 != null) {
                                                                                        i2 = R.id.tvTime;
                                                                                        TextView textView10 = (TextView) view.findViewById(R.id.tvTime);
                                                                                        if (textView10 != null) {
                                                                                            return new ItemDarkTradeBinding((FrameLayout) view, frameLayout, imageTextView, textView, imageView, imageView2, imageView3, linearLayout, linearLayout2, textView2, relativeLayout, recyclerView, squareGridView, imageView4, textView3, textView4, textView5, textView6, textView7, textView8, textView9, textView10);
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
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemDarkTradeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemDarkTradeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_dark_trade, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
