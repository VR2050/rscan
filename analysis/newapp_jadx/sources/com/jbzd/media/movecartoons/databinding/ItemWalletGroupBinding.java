package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemWalletGroupBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout layoutItemCenter;

    @NonNull
    public final ConstraintLayout llCard;

    @NonNull
    public final LinearLayout llGroup;

    @NonNull
    public final BLTextView promotionTips;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvGiftTips;

    @NonNull
    public final ImageTextView tvName;

    @NonNull
    public final TextView tvPrice;

    @NonNull
    public final TextView tvRateTips;

    @NonNull
    public final BLTextView tvTime;

    private ItemWalletGroupBinding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull ConstraintLayout constraintLayout, @NonNull LinearLayout linearLayout2, @NonNull BLTextView bLTextView, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull BLTextView bLTextView2) {
        this.rootView = linearLayout;
        this.layoutItemCenter = relativeLayout;
        this.llCard = constraintLayout;
        this.llGroup = linearLayout2;
        this.promotionTips = bLTextView;
        this.tvGiftTips = textView;
        this.tvName = imageTextView;
        this.tvPrice = textView2;
        this.tvRateTips = textView3;
        this.tvTime = bLTextView2;
    }

    @NonNull
    public static ItemWalletGroupBinding bind(@NonNull View view) {
        int i2 = R.id.layout_item_center;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.layout_item_center);
        if (relativeLayout != null) {
            i2 = R.id.ll_card;
            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.ll_card);
            if (constraintLayout != null) {
                i2 = R.id.ll_group;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_group);
                if (linearLayout != null) {
                    i2 = R.id.promotion_tips;
                    BLTextView bLTextView = (BLTextView) view.findViewById(R.id.promotion_tips);
                    if (bLTextView != null) {
                        i2 = R.id.tv_giftTips;
                        TextView textView = (TextView) view.findViewById(R.id.tv_giftTips);
                        if (textView != null) {
                            i2 = R.id.tv_name;
                            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.tv_name);
                            if (imageTextView != null) {
                                i2 = R.id.tv_price;
                                TextView textView2 = (TextView) view.findViewById(R.id.tv_price);
                                if (textView2 != null) {
                                    i2 = R.id.tv_rateTips;
                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_rateTips);
                                    if (textView3 != null) {
                                        i2 = R.id.tv_time;
                                        BLTextView bLTextView2 = (BLTextView) view.findViewById(R.id.tv_time);
                                        if (bLTextView2 != null) {
                                            return new ItemWalletGroupBinding((LinearLayout) view, relativeLayout, constraintLayout, linearLayout, bLTextView, textView, imageTextView, textView2, textView3, bLTextView2);
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
    public static ItemWalletGroupBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemWalletGroupBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_wallet_group, viewGroup, false);
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
