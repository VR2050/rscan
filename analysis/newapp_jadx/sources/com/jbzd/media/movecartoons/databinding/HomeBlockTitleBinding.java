package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class HomeBlockTitleBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvMore;

    @NonNull
    public final LinearLayout llBlockTitle;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvTitle;

    private HomeBlockTitleBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull LinearLayout linearLayout2, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.itvMore = imageTextView;
        this.llBlockTitle = linearLayout2;
        this.tvTitle = textView;
    }

    @NonNull
    public static HomeBlockTitleBinding bind(@NonNull View view) {
        int i2 = R.id.itv_more;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_more);
        if (imageTextView != null) {
            i2 = R.id.ll_block_title;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_block_title);
            if (linearLayout != null) {
                i2 = R.id.tv_title;
                TextView textView = (TextView) view.findViewById(R.id.tv_title);
                if (textView != null) {
                    return new HomeBlockTitleBinding((LinearLayout) view, imageTextView, linearLayout, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static HomeBlockTitleBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static HomeBlockTitleBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.home_block_title, viewGroup, false);
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
