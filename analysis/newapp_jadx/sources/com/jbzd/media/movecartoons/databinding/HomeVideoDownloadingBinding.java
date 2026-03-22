package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class HomeVideoDownloadingBinding implements ViewBinding {

    @NonNull
    public final TextView btnDel;

    @NonNull
    public final TextView btnStatusLeft;

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ImageView ivEdit;

    @NonNull
    public final ImageView ivFlag;

    @NonNull
    public final ImageView ivVideo;

    @NonNull
    public final ProgressBar pbProgressDownload;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvDownload;

    @NonNull
    public final TextView tvDuration;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final ImageTextView tvWantLook;

    private HomeVideoDownloadingBinding(@NonNull ConstraintLayout constraintLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ProgressBar progressBar, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull ImageTextView imageTextView2) {
        this.rootView = constraintLayout;
        this.btnDel = textView;
        this.btnStatusLeft = textView2;
        this.itvPrice = imageTextView;
        this.ivEdit = imageView;
        this.ivFlag = imageView2;
        this.ivVideo = imageView3;
        this.pbProgressDownload = progressBar;
        this.tvDownload = textView3;
        this.tvDuration = textView4;
        this.tvName = textView5;
        this.tvWantLook = imageTextView2;
    }

    @NonNull
    public static HomeVideoDownloadingBinding bind(@NonNull View view) {
        int i2 = R.id.btn_del;
        TextView textView = (TextView) view.findViewById(R.id.btn_del);
        if (textView != null) {
            i2 = R.id.btn_status_left;
            TextView textView2 = (TextView) view.findViewById(R.id.btn_status_left);
            if (textView2 != null) {
                i2 = R.id.itv_price;
                ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_price);
                if (imageTextView != null) {
                    i2 = R.id.iv_edit;
                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_edit);
                    if (imageView != null) {
                        i2 = R.id.iv_flag;
                        ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_flag);
                        if (imageView2 != null) {
                            i2 = R.id.iv_video;
                            ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_video);
                            if (imageView3 != null) {
                                i2 = R.id.pb_progress_download;
                                ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.pb_progress_download);
                                if (progressBar != null) {
                                    i2 = R.id.tvDownload;
                                    TextView textView3 = (TextView) view.findViewById(R.id.tvDownload);
                                    if (textView3 != null) {
                                        i2 = R.id.tv_duration;
                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_duration);
                                        if (textView4 != null) {
                                            i2 = R.id.tv_name;
                                            TextView textView5 = (TextView) view.findViewById(R.id.tv_name);
                                            if (textView5 != null) {
                                                i2 = R.id.tv_wantLook;
                                                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.tv_wantLook);
                                                if (imageTextView2 != null) {
                                                    return new HomeVideoDownloadingBinding((ConstraintLayout) view, textView, textView2, imageTextView, imageView, imageView2, imageView3, progressBar, textView3, textView4, textView5, imageTextView2);
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
    public static HomeVideoDownloadingBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static HomeVideoDownloadingBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.home_video_downloading, viewGroup, false);
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
