package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.AspectRatioLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemHistoryBinding implements ViewBinding {

    @NonNull
    public final AspectRatioLayout flRoot;

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    public final ImageView ivImg;

    @NonNull
    public final ImageView ivVipTag;

    @NonNull
    public final LinearLayout llContent;

    @NonNull
    public final LinearLayout llMoney;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvClickNum;

    @NonNull
    public final TextView tvDuration;

    @NonNull
    public final TextView tvHistory;

    @NonNull
    public final TextView tvMoney;

    private ItemHistoryBinding(@NonNull LinearLayout linearLayout, @NonNull AspectRatioLayout aspectRatioLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = linearLayout;
        this.flRoot = aspectRatioLayout;
        this.ivCenterPlayicon = textView;
        this.ivImg = imageView;
        this.ivVipTag = imageView2;
        this.llContent = linearLayout2;
        this.llMoney = linearLayout3;
        this.tvClickNum = textView2;
        this.tvDuration = textView3;
        this.tvHistory = textView4;
        this.tvMoney = textView5;
    }

    @NonNull
    public static ItemHistoryBinding bind(@NonNull View view) {
        int i2 = R.id.flRoot;
        AspectRatioLayout aspectRatioLayout = (AspectRatioLayout) view.findViewById(R.id.flRoot);
        if (aspectRatioLayout != null) {
            i2 = R.id.iv_center_playicon;
            TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
            if (textView != null) {
                i2 = R.id.iv_img;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_img);
                if (imageView != null) {
                    i2 = R.id.ivVipTag;
                    ImageView imageView2 = (ImageView) view.findViewById(R.id.ivVipTag);
                    if (imageView2 != null) {
                        LinearLayout linearLayout = (LinearLayout) view;
                        i2 = R.id.llMoney;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.llMoney);
                        if (linearLayout2 != null) {
                            i2 = R.id.tv_click_num;
                            TextView textView2 = (TextView) view.findViewById(R.id.tv_click_num);
                            if (textView2 != null) {
                                i2 = R.id.tvDuration;
                                TextView textView3 = (TextView) view.findViewById(R.id.tvDuration);
                                if (textView3 != null) {
                                    i2 = R.id.tvHistory;
                                    TextView textView4 = (TextView) view.findViewById(R.id.tvHistory);
                                    if (textView4 != null) {
                                        i2 = R.id.tvMoney;
                                        TextView textView5 = (TextView) view.findViewById(R.id.tvMoney);
                                        if (textView5 != null) {
                                            return new ItemHistoryBinding(linearLayout, aspectRatioLayout, textView, imageView, imageView2, linearLayout, linearLayout2, textView2, textView3, textView4, textView5);
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
    public static ItemHistoryBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemHistoryBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_history, viewGroup, false);
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
