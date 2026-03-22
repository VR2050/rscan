package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
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
public final class DialogDownloadBottomBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvProgressTxt;

    @NonNull
    public final View outsideView;

    @NonNull
    public final ProgressBar pbProgress;

    @NonNull
    public final RelativeLayout rlDownlod;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvCancel;

    @NonNull
    public final TextView tvGoPhotos;

    private DialogDownloadBottomBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull View view, @NonNull ProgressBar progressBar, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.itvProgressTxt = imageTextView;
        this.outsideView = view;
        this.pbProgress = progressBar;
        this.rlDownlod = relativeLayout;
        this.tvCancel = textView;
        this.tvGoPhotos = textView2;
    }

    @NonNull
    public static DialogDownloadBottomBinding bind(@NonNull View view) {
        int i2 = R.id.itv_progressTxt;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_progressTxt);
        if (imageTextView != null) {
            i2 = R.id.outside_view;
            View findViewById = view.findViewById(R.id.outside_view);
            if (findViewById != null) {
                i2 = R.id.pb_progress;
                ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.pb_progress);
                if (progressBar != null) {
                    i2 = R.id.rl_downlod;
                    RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_downlod);
                    if (relativeLayout != null) {
                        i2 = R.id.tv_cancel;
                        TextView textView = (TextView) view.findViewById(R.id.tv_cancel);
                        if (textView != null) {
                            i2 = R.id.tv_goPhotos;
                            TextView textView2 = (TextView) view.findViewById(R.id.tv_goPhotos);
                            if (textView2 != null) {
                                return new DialogDownloadBottomBinding((LinearLayout) view, imageTextView, findViewById, progressBar, relativeLayout, textView, textView2);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogDownloadBottomBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogDownloadBottomBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_download_bottom, viewGroup, false);
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
