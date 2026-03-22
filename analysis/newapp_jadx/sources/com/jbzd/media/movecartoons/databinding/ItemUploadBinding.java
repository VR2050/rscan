package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemUploadBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvDuration;

    @NonNull
    public final ImageView ivImg;

    @NonNull
    public final LinearLayout llProgress;

    @NonNull
    public final ProgressBar pbProgress;

    @NonNull
    public final RelativeLayout rlImg;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvEdit;

    @NonNull
    public final TextView tvMore;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvProgress;

    @NonNull
    public final TextView tvTime;

    @NonNull
    public final TextView tvTips;

    private ItemUploadBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull ProgressBar progressBar, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6) {
        this.rootView = linearLayout;
        this.itvDuration = imageTextView;
        this.ivImg = imageView;
        this.llProgress = linearLayout2;
        this.pbProgress = progressBar;
        this.rlImg = relativeLayout;
        this.tvEdit = textView;
        this.tvMore = textView2;
        this.tvName = textView3;
        this.tvProgress = textView4;
        this.tvTime = textView5;
        this.tvTips = textView6;
    }

    @NonNull
    public static ItemUploadBinding bind(@NonNull View view) {
        int i2 = R.id.itv_duration;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_duration);
        if (imageTextView != null) {
            i2 = R.id.iv_img;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_img);
            if (imageView != null) {
                i2 = R.id.ll_progress;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_progress);
                if (linearLayout != null) {
                    i2 = R.id.pb_progress;
                    ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.pb_progress);
                    if (progressBar != null) {
                        i2 = R.id.rl_img;
                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_img);
                        if (relativeLayout != null) {
                            i2 = R.id.tv_edit;
                            TextView textView = (TextView) view.findViewById(R.id.tv_edit);
                            if (textView != null) {
                                i2 = R.id.tv_more;
                                TextView textView2 = (TextView) view.findViewById(R.id.tv_more);
                                if (textView2 != null) {
                                    i2 = R.id.tv_name;
                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_name);
                                    if (textView3 != null) {
                                        i2 = R.id.tv_progress;
                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_progress);
                                        if (textView4 != null) {
                                            i2 = R.id.tv_time;
                                            TextView textView5 = (TextView) view.findViewById(R.id.tv_time);
                                            if (textView5 != null) {
                                                i2 = R.id.tv_tips;
                                                TextView textView6 = (TextView) view.findViewById(R.id.tv_tips);
                                                if (textView6 != null) {
                                                    return new ItemUploadBinding((LinearLayout) view, imageTextView, imageView, linearLayout, progressBar, relativeLayout, textView, textView2, textView3, textView4, textView5, textView6);
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
    public static ItemUploadBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemUploadBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_upload, viewGroup, false);
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
